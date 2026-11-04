// Package crawler performs a lightweight same-origin crawl: starting from a seed
// URL it follows in-scope links, feeding each fetched page back through the
// normal flow pipeline (history + passive scanning). It only visits hosts that
// the provided InScope predicate permits.
package crawler

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"interlace/internal/model"
)

const maxBody = 8 << 20

// Seed is the starting point for a crawl.
type Seed struct {
	URL string
}

// Progress reports a single crawled page.
type Progress struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Found  int    `json:"found"`
	Error  string `json:"error,omitempty"`
}

var linkRe = regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']([^"'#]+)["']`)

// Applier adds session headers to a request (optional).
type Applier interface{ Apply(host string, h http.Header) }

// Crawl visits up to maxPages in-scope pages reachable from seed. For each page
// it builds a model.Flow and calls onFlow (which the caller wires to storage and
// passive scanning). inScope gates every host visited. emit reports progress.
func Crawl(ctx context.Context, seed Seed, insecure bool, inScope func(host string) bool,
	onFlow func(*model.Flow), emit func(Progress), maxPages int, session Applier) (int, error) {

	if maxPages <= 0 || maxPages > 500 {
		maxPages = 100
	}
	start, err := url.Parse(seed.URL)
	if err != nil {
		return 0, err
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec
			ForceAttemptHTTP2: true,
		},
		CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}

	visited := map[string]bool{}
	queue := []*url.URL{start}
	count := 0

	for len(queue) > 0 && count < maxPages {
		if ctx.Err() != nil {
			return count, ctx.Err()
		}
		u := queue[0]
		queue = queue[1:]
		key := u.Scheme + "://" + u.Host + u.Path
		if visited[key] {
			continue
		}
		visited[key] = true
		if !inScope(u.Hostname()) {
			continue
		}

		flow, body, status, ferr := fetch(ctx, client, u, session)
		count++
		if ferr != nil {
			emit(Progress{URL: u.String(), Error: ferr.Error()})
			continue
		}
		onFlow(flow)

		found := 0
		if isHTML(flow.ContentType) {
			for _, link := range extractLinks(body) {
				ref, err := u.Parse(link)
				if err != nil {
					continue
				}
				if ref.Scheme != "http" && ref.Scheme != "https" {
					continue
				}
				if ref.Host != start.Host { // same-origin only
					continue
				}
				ref.Fragment = ""
				k := ref.Scheme + "://" + ref.Host + ref.Path
				if !visited[k] {
					queue = append(queue, ref)
					found++
				}
			}
		}
		emit(Progress{URL: u.String(), Status: status, Found: found})
	}
	return count, nil
}

func fetch(ctx context.Context, client *http.Client, u *url.URL, session Applier) (*model.Flow, []byte, int, error) {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, 0, err
	}
	req.Header.Set("User-Agent", "Interlace-Crawler")
	if session != nil {
		session.Apply(req.URL.Host, req.Header)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))

	flow := &model.Flow{
		Timestamp:   start,
		Method:      http.MethodGet,
		Scheme:      u.Scheme,
		Host:        u.Hostname(),
		Path:        u.RequestURI(),
		URL:         u.String(),
		ReqHeaders:  req.Header,
		StatusCode:  resp.StatusCode,
		RespHeaders: resp.Header,
		RespBody:    body,
		ContentType: resp.Header.Get("Content-Type"),
		DurationMs:  time.Since(start).Milliseconds(),
	}
	return flow, body, resp.StatusCode, nil
}

func extractLinks(body []byte) []string {
	var out []string
	for _, m := range linkRe.FindAllSubmatch(body, -1) {
		out = append(out, string(m[1]))
	}
	return out
}

func isHTML(ct string) bool { return strings.Contains(strings.ToLower(ct), "text/html") }
