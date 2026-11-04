// Package fuzzer implements Interlace's Intruder-style request fuzzer. Payload
// positions are marked in a raw request template with § markers (the text
// between a pair of § is that position's base value). Attack types control how
// payload lists are combined across positions.
package fuzzer

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"interlace/internal/repeater"
)

// maxRequests caps a single fuzzing run as a safety brake against runaway
// cluster-bomb products.
const maxRequests = 5000

// Attack types.
const (
	Sniper      = "sniper"
	Pitchfork   = "pitchfork"
	ClusterBomb = "clusterbomb"
)

// Config describes a fuzzing run.
type Config struct {
	Scheme      string     `json:"scheme"`
	Host        string     `json:"host"`
	Template    string     `json:"template"` // raw request with § position markers
	Attack      string     `json:"attack"`
	Payloads    [][]string `json:"payloads"` // one list per position (sniper uses the first)
	Grep        string     `json:"grep"`     // flag responses containing this string
	Extract     string     `json:"extract"`  // regex; first match is pulled into Result.Extracted
	Concurrency int        `json:"concurrency"`
	DelayMs     int        `json:"delayMs"`
}

// Result is one completed fuzz request.
type Result struct {
	Index      int      `json:"index"`
	Payloads   []string `json:"payloads"` // value placed in each marked position
	Status     int      `json:"status"`
	Length     int      `json:"length"`
	DurationMs int64    `json:"durationMs"`
	Matched    bool     `json:"matched"`
	Extracted  string   `json:"extracted,omitempty"`
	Error      string   `json:"error,omitempty"`
}

type segment struct {
	lit string
	pos int // -1 for a literal segment
}

// Run executes the fuzzing job, calling emit for each completed result. It
// returns the total number of requests issued.
func Run(ctx context.Context, cfg Config, sender *repeater.Sender, emit func(Result)) (int, error) {
	segs, base, err := parseTemplate(cfg.Template)
	if err != nil {
		return 0, err
	}
	n := len(base)
	if n == 0 {
		return 0, fmt.Errorf("no payload positions: wrap each injection point in § markers")
	}

	assigns, truncated, err := assignments(cfg, base, n)
	if err != nil {
		return 0, err
	}

	conc := cfg.Concurrency
	if conc <= 0 {
		conc = 10
	}
	if conc > 100 {
		conc = 100
	}

	var extractRe *regexp.Regexp
	if cfg.Extract != "" {
		extractRe, _ = regexp.Compile(cfg.Extract)
	}

	type job struct {
		idx  int
		vals []string
	}
	jobs := make(chan job)
	var wg sync.WaitGroup

	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				raw := render(segs, j.vals)
				resp := sender.Send(ctx, repeater.Request{Scheme: cfg.Scheme, Host: cfg.Host, Raw: raw})
				res := Result{
					Index:      j.idx,
					Payloads:   j.vals,
					Status:     resp.Status,
					Length:     resp.BodyLen,
					DurationMs: resp.DurationMs,
					Error:      resp.Error,
				}
				if cfg.Grep != "" && resp.Error == "" {
					res.Matched = strings.Contains(resp.Body, cfg.Grep) ||
						strings.Contains(resp.Headers, cfg.Grep)
				}
				if extractRe != nil && resp.Error == "" {
					if m := extractRe.FindStringSubmatch(resp.Body); m != nil {
						res.Extracted = m[len(m)-1] // last group, or whole match
					}
				}
				emit(res)
				if cfg.DelayMs > 0 {
					select {
					case <-ctx.Done():
					case <-time.After(time.Duration(cfg.DelayMs) * time.Millisecond):
					}
				}
			}
		}()
	}

	for i, vals := range assigns {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return i, ctx.Err()
		case jobs <- job{idx: i, vals: vals}:
		}
	}
	close(jobs)
	wg.Wait()

	if truncated {
		return len(assigns), fmt.Errorf("capped at %d requests", maxRequests)
	}
	return len(assigns), nil
}

// assignments builds the per-request position value sets for the attack type.
func assignments(cfg Config, base []string, n int) (out [][]string, truncated bool, err error) {
	add := func(v []string) bool {
		if len(out) >= maxRequests {
			truncated = true
			return false
		}
		out = append(out, v)
		return true
	}

	switch cfg.Attack {
	case Sniper, "":
		if len(cfg.Payloads) == 0 || len(cfg.Payloads[0]) == 0 {
			return nil, false, fmt.Errorf("sniper needs a payload list")
		}
		list := cfg.Payloads[0]
		for p := 0; p < n; p++ {
			for _, v := range list {
				a := append([]string(nil), base...)
				a[p] = v
				if !add(a) {
					return out, truncated, nil
				}
			}
		}
	case Pitchfork:
		if len(cfg.Payloads) < n {
			return nil, false, fmt.Errorf("pitchfork needs one payload list per position (%d)", n)
		}
		m := len(cfg.Payloads[0])
		for p := 1; p < n; p++ {
			if len(cfg.Payloads[p]) < m {
				m = len(cfg.Payloads[p])
			}
		}
		for i := 0; i < m; i++ {
			a := make([]string, n)
			for p := 0; p < n; p++ {
				a[p] = cfg.Payloads[p][i]
			}
			if !add(a) {
				return out, truncated, nil
			}
		}
	case ClusterBomb:
		if len(cfg.Payloads) < n {
			return nil, false, fmt.Errorf("cluster bomb needs one payload list per position (%d)", n)
		}
		idx := make([]int, n)
		for {
			a := make([]string, n)
			for p := 0; p < n; p++ {
				list := cfg.Payloads[p]
				if len(list) == 0 {
					return nil, false, fmt.Errorf("payload list for position %d is empty", p+1)
				}
				a[p] = list[idx[p]]
			}
			if !add(a) {
				return out, truncated, nil
			}
			// increment odometer
			k := n - 1
			for k >= 0 {
				idx[k]++
				if idx[k] < len(cfg.Payloads[k]) {
					break
				}
				idx[k] = 0
				k--
			}
			if k < 0 {
				break
			}
		}
	default:
		return nil, false, fmt.Errorf("unknown attack type %q", cfg.Attack)
	}
	return out, truncated, nil
}

// parseTemplate splits a template on § markers. Even-indexed parts are literal
// text; odd-indexed parts are position base values.
func parseTemplate(tpl string) (segs []segment, base []string, err error) {
	parts := strings.Split(tpl, "§")
	if len(parts)%2 == 0 {
		return nil, nil, fmt.Errorf("unbalanced § markers (need pairs around each position)")
	}
	for i, p := range parts {
		if i%2 == 0 {
			segs = append(segs, segment{lit: p, pos: -1})
		} else {
			idx := len(base)
			base = append(base, p)
			segs = append(segs, segment{pos: idx})
		}
	}
	return segs, base, nil
}

func render(segs []segment, vals []string) string {
	var b strings.Builder
	for _, s := range segs {
		if s.pos < 0 {
			b.WriteString(s.lit)
		} else {
			b.WriteString(vals[s.pos])
		}
	}
	return b.String()
}
