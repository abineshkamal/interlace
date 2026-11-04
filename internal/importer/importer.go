// Package importer parses API specifications (OpenAPI 3 / Swagger 2 / Postman
// collections) into concrete HTTP requests that can be sent to seed Interlace's
// history and scan targets.
package importer

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Request is one concrete request derived from a spec.
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
}

// Parse detects the spec format and returns the requests. baseURL overrides the
// server URL found in the spec (useful when the spec omits it or targets prod).
func Parse(spec []byte, baseURL string) ([]Request, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(spec, &probe); err != nil {
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}
	switch {
	case probe["openapi"] != nil || probe["swagger"] != nil:
		return parseOpenAPI(spec, baseURL)
	case probe["item"] != nil && probe["info"] != nil:
		return parsePostman(spec, baseURL)
	default:
		return nil, fmt.Errorf("unrecognized spec (expected OpenAPI, Swagger or Postman)")
	}
}

// --- OpenAPI / Swagger ---

func parseOpenAPI(spec []byte, baseURL string) ([]Request, error) {
	var doc struct {
		Swagger  string `json:"swagger"`
		Host     string `json:"host"`
		BasePath string `json:"basePath"`
		Schemes  []string
		Servers  []struct {
			URL string `json:"url"`
		} `json:"servers"`
		Paths map[string]map[string]struct {
			Parameters []param `json:"parameters"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(spec, &doc); err != nil {
		return nil, err
	}
	base := strings.TrimRight(baseURL, "/")
	if base == "" {
		if len(doc.Servers) > 0 {
			base = strings.TrimRight(doc.Servers[0].URL, "/")
		} else if doc.Host != "" { // Swagger 2
			scheme := "https"
			if len(doc.Schemes) > 0 {
				scheme = doc.Schemes[0]
			}
			base = scheme + "://" + doc.Host + doc.BasePath
		}
	}
	if base == "" {
		return nil, fmt.Errorf("no server URL in spec; provide a base URL")
	}

	methods := map[string]bool{"get": true, "post": true, "put": true, "delete": true, "patch": true}
	var out []Request
	for p, ops := range doc.Paths {
		for method, op := range ops {
			if !methods[strings.ToLower(method)] {
				continue
			}
			path := p
			var query []string
			for _, pr := range op.Parameters {
				switch pr.In {
				case "path":
					path = strings.ReplaceAll(path, "{"+pr.Name+"}", "1")
				case "query":
					query = append(query, pr.Name+"=test")
				}
			}
			// Any remaining {param} placeholders.
			path = replaceBraces(path)
			url := base + path
			if len(query) > 0 {
				url += "?" + strings.Join(query, "&")
			}
			req := Request{Method: strings.ToUpper(method), URL: url, Headers: map[string]string{}}
			if method == "post" || method == "put" || method == "patch" {
				req.Headers["Content-Type"] = "application/json"
				req.Body = "{}"
			}
			out = append(out, req)
		}
	}
	return out, nil
}

type param struct {
	Name string `json:"name"`
	In   string `json:"in"`
}

func replaceBraces(p string) string {
	for {
		i := strings.IndexByte(p, '{')
		if i < 0 {
			return p
		}
		j := strings.IndexByte(p[i:], '}')
		if j < 0 {
			return p
		}
		p = p[:i] + "1" + p[i+j+1:]
	}
}

// --- Postman ---

func parsePostman(spec []byte, baseURL string) ([]Request, error) {
	var doc struct {
		Item []postmanItem `json:"item"`
	}
	if err := json.Unmarshal(spec, &doc); err != nil {
		return nil, err
	}
	var out []Request
	var walk func(items []postmanItem)
	walk = func(items []postmanItem) {
		for _, it := range items {
			if len(it.Item) > 0 {
				walk(it.Item)
			}
			if it.Request != nil {
				if req := postmanToRequest(it.Request, baseURL); req != nil {
					out = append(out, *req)
				}
			}
		}
	}
	walk(doc.Item)
	return out, nil
}

type postmanItem struct {
	Name    string          `json:"name"`
	Item    []postmanItem   `json:"item"`
	Request *postmanRequest `json:"request"`
}

type postmanRequest struct {
	Method string          `json:"method"`
	Header []postmanHeader `json:"header"`
	URL    json.RawMessage `json:"url"`
	Body   *struct {
		Raw string `json:"raw"`
	} `json:"body"`
}

type postmanHeader struct {
	Key, Value string
}

func postmanToRequest(pr *postmanRequest, baseURL string) *Request {
	raw := postmanURL(pr.URL)
	if raw == "" {
		return nil
	}
	if baseURL != "" && strings.HasPrefix(raw, "/") {
		raw = strings.TrimRight(baseURL, "/") + raw
	}
	req := &Request{Method: strings.ToUpper(pr.Method), URL: raw, Headers: map[string]string{}}
	if req.Method == "" {
		req.Method = "GET"
	}
	for _, h := range pr.Header {
		if h.Key != "" {
			req.Headers[h.Key] = h.Value
		}
	}
	if pr.Body != nil {
		req.Body = pr.Body.Raw
	}
	return req
}

// postmanURL handles both string and object URL forms.
func postmanURL(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var obj struct {
		Raw string `json:"raw"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		return obj.Raw
	}
	return ""
}
