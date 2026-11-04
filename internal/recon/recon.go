// Package recon implements active reconnaissance: content discovery (brute-
// forcing hidden paths) and parameter mining (discovering unlinked parameters).
// Both send requests, so callers must confirm the target is in scope.
package recon

import (
	"context"
	"crypto/tls"
	_ "embed"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"interlace/internal/model"
)

//go:embed wordlist_paths.txt
var pathWordlist string

//go:embed wordlist_params.txt
var paramWordlist string

// Paths returns the built-in content-discovery wordlist.
func Paths() []string { return lines(pathWordlist) }

// Params returns the built-in parameter-mining wordlist.
func Params() []string { return lines(paramWordlist) }

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func client(insecure bool) *http.Client {
	return &http.Client{
		Timeout: 12 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec
			MaxIdleConnsPerHost: 20,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// DiscoveryResult reports one probed path.
type DiscoveryResult struct {
	Path   string `json:"path"`
	Status int    `json:"status"`
	Length int    `json:"length"`
	Found  bool   `json:"found"`
}

// Session applies auth headers to recon requests (optional).
type Session interface{ Apply(http.Header) }

// ContentDiscovery brute-forces words under scheme://host, reporting paths that
// differ from the host's not-found baseline and feeding found pages to onFlow.
func ContentDiscovery(ctx context.Context, scheme, host string, words []string, insecure bool,
	onFlow func(*model.Flow), sess Session, emit func(DiscoveryResult), concurrency int) (int, error) {

	c := client(insecure)
	base := scheme + "://" + host

	// Baseline from a random path to detect soft-404s.
	baseStatus, baseLen := probe(ctx, c, base+"/interlace-not-here-"+token(), sess)

	if concurrency <= 0 || concurrency > 50 {
		concurrency = 20
	}
	jobs := make(chan string)
	var wg sync.WaitGroup
	var mu sync.Mutex
	found := 0

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range jobs {
				if ctx.Err() != nil {
					return
				}
				u := base + "/" + word
				flow, status, length := fetch(ctx, c, u, sess)
				isFound := status != 404 && !(status == baseStatus && approxEqual(length, baseLen))
				if isFound && flow != nil && onFlow != nil {
					onFlow(flow)
				}
				mu.Lock()
				if isFound {
					found++
				}
				mu.Unlock()
				emit(DiscoveryResult{Path: "/" + word, Status: status, Length: length, Found: isFound})
			}
		}()
	}
	for _, w := range words {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return found, ctx.Err()
		case jobs <- w:
		}
	}
	close(jobs)
	wg.Wait()
	return found, nil
}

// ParamResult reports a discovered parameter.
type ParamResult struct {
	Param    string `json:"param"`
	Evidence string `json:"evidence"`
}

// ParamMine sends the template request with each candidate parameter added and
// reports those that change the response (reflected or altered length).
func ParamMine(ctx context.Context, scheme, host, method, path string, header http.Header, words []string,
	insecure bool, sess Session, emit func(ParamResult), concurrency int) (int, error) {

	c := client(insecure)
	baseURL := scheme + "://" + host + path

	baseBody, baseLen := getBody(ctx, c, method, baseURL, header, sess)

	if concurrency <= 0 || concurrency > 30 {
		concurrency = 12
	}
	jobs := make(chan string)
	var wg sync.WaitGroup
	var mu sync.Mutex
	found := 0

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				if ctx.Err() != nil {
					return
				}
				marker := "ilxpm" + token()
				u := addParam(baseURL, p, marker)
				body, ln := getBody(ctx, c, method, u, header, sess)
				reflected := strings.Contains(body, marker)
				sizeChanged := !approxEqual(ln, baseLen) && body != baseBody
				if reflected || sizeChanged {
					ev := "length changed"
					if reflected {
						ev = "value reflected in response"
					}
					mu.Lock()
					found++
					mu.Unlock()
					emit(ParamResult{Param: p, Evidence: ev})
				}
			}
		}()
	}
	for _, p := range words {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return found, ctx.Err()
		case jobs <- p:
		}
	}
	close(jobs)
	wg.Wait()
	return found, nil
}

// --- helpers ---

func probe(ctx context.Context, c *http.Client, u string, sess Session) (int, int) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, 0
	}
	req.Header.Set("User-Agent", "Interlace-Recon")
	if sess != nil {
		sess.Apply(req.Header)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, 0
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, len(b)
}

func fetch(ctx context.Context, c *http.Client, u string, sess Session) (*model.Flow, int, int) {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, 0
	}
	req.Header.Set("User-Agent", "Interlace-Recon")
	if sess != nil {
		sess.Apply(req.Header)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, 0, 0
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	pu, _ := url.Parse(u)
	flow := &model.Flow{
		Timestamp: start, Method: http.MethodGet, Scheme: pu.Scheme, Host: pu.Hostname(),
		Path: pu.RequestURI(), URL: u, ReqHeaders: req.Header, StatusCode: resp.StatusCode,
		RespHeaders: resp.Header, RespBody: body, ContentType: resp.Header.Get("Content-Type"),
		DurationMs: time.Since(start).Milliseconds(),
	}
	return flow, resp.StatusCode, len(body)
}

func getBody(ctx context.Context, c *http.Client, method, u string, header http.Header, sess Session) (string, int) {
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return "", 0
	}
	for k, vv := range header {
		if strings.EqualFold(k, "host") || strings.EqualFold(k, "content-length") {
			continue
		}
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}
	if sess != nil {
		sess.Apply(req.Header)
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", 0
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return string(b), len(b)
}

func addParam(rawURL, key, val string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set(key, val)
	u.RawQuery = q.Encode()
	return u.String()
}

func approxEqual(a, b int) bool {
	if a == b {
		return true
	}
	d := math.Abs(float64(a - b))
	return d/math.Max(float64(a), float64(b)+1) < 0.02 // within 2%
}

var tokenSeq int
var tokenMu sync.Mutex

func token() string {
	tokenMu.Lock()
	tokenSeq++
	n := tokenSeq
	tokenMu.Unlock()
	return fmt.Sprintf("%d%d", time.Now().UnixNano()%1000000, n)
}
