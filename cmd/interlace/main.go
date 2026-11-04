// Command interlace runs the Interlace intercepting proxy, persists captured
// traffic to a project database, and serves the web UI plus a local API for
// inspecting history and downloading the root CA certificate.
package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"

	"github.com/gorilla/websocket"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"interlace/internal/ca"
	"interlace/internal/crawler"
	"interlace/internal/fuzzer"
	"interlace/internal/hub"
	"interlace/internal/intercept"
	"interlace/internal/macro"
	"interlace/internal/matchreplace"
	"interlace/internal/model"
	"interlace/internal/oob"
	"interlace/internal/proxy"
	"interlace/internal/recon"
	"interlace/internal/repeater"
	"interlace/internal/scanner"
	"interlace/internal/scheduler"
	"interlace/internal/scope"
	"interlace/internal/session"
	"interlace/internal/store"
	"interlace/internal/wsintercept"
)

//go:embed web/index.html
var webFS embed.FS

//go:embed web/report.tmpl
var reportTmplSrc string

// version is stamped into the UI/report; bump per release.
const version = "0.1.0"

var reportTmpl = template.Must(template.New("report").Parse(reportTmplSrc))

func main() {
	var (
		proxyAddr = flag.String("proxy", "127.0.0.1:8080", "proxy listen address")
		apiAddr   = flag.String("api", "127.0.0.1:8081", "web UI + API listen address")
		dataDir   = flag.String("data", defaultDataDir(), "data directory (CA + project db)")
		insecure  = flag.Bool("insecure-upstream", true, "accept invalid upstream TLS certificates")
		openUI    = flag.Bool("open", true, "open the UI in the default browser on startup")
		oobAddr   = flag.String("oob", "127.0.0.1:8082", "out-of-band interaction listener address")
		oobURL    = flag.String("oob-url", "", "public base URL for OOB callbacks (default http://<oob>)")
	)
	flag.Parse()

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		log.Fatalf("create data dir: %v", err)
	}

	authority, err := ca.LoadOrCreate(filepath.Join(*dataDir, "ca"))
	if err != nil {
		log.Fatalf("certificate authority: %v", err)
	}

	st, err := store.Open(filepath.Join(*dataDir, "project.db"))
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()

	h := hub.New()          // live flows
	findHub := hub.New()    // live findings
	interHub := hub.New()   // intercept changes
	wsHub := hub.New()        // live websocket messages
	wsInterHub := hub.New()   // ws intercept changes
	ic := intercept.New(interHub)
	wsIc := wsintercept.New(wsInterHub)
	mr := matchreplace.Load(filepath.Join(*dataDir, "matchreplace.json"))

	// processFlow stores a captured flow, broadcasts it, and runs passive checks.
	// Shared by the proxy and the crawler.
	processFlow := func(f *model.Flow) {
		id, err := st.Insert(f)
		if err != nil {
			log.Printf("store flow: %v", err)
			return
		}
		f.ID = id
		if msg, err := json.Marshal(summarize(f)); err == nil {
			h.Broadcast(msg)
		}
		for _, find := range scanner.Scan(f) {
			fid, inserted, err := st.InsertFinding(&find)
			if err != nil {
				log.Printf("store finding: %v", err)
				continue
			}
			if !inserted {
				continue
			}
			find.ID = fid
			if msg, err := json.Marshal(find); err == nil {
				findHub.Broadcast(msg)
			}
		}
	}

	p := proxy.New(proxy.Options{
		Addr:             *proxyAddr,
		CA:               authority,
		InsecureUpstream: *insecure,
		Interceptor:      ic,
		WSInterceptor:    wsIc,
		Rewriter:         mr,
		OnFlow:           processFlow,
		OnWS: func(m *model.WSMessage) {
			id, err := st.InsertWS(m)
			if err != nil {
				log.Printf("store ws: %v", err)
				return
			}
			m.ID = id
			if msg, err := json.Marshal(m); err == nil {
				wsHub.Broadcast(msg)
			}
		},
	})

	rep := repeater.New(*insecure)
	sc := scope.Load(filepath.Join(*dataDir, "scope.json"))
	sess := session.Load(filepath.Join(*dataDir, "session.json"))
	rep.SetSession(sess)
	macroStore := macro.Load(filepath.Join(*dataDir, "macro.json"))

	// Plugin SDK: load any custom active-check rules the user has added.
	if n, err := scanner.LoadRules(filepath.Join(*dataDir, "rules")); err != nil {
		log.Printf("custom rules: %v", err)
	} else if n > 0 {
		log.Printf("loaded %d custom active-scan rule(s)", n)
	}

	// Out-of-band interaction server (for blind vulnerability detection).
	oobHub := hub.New()
	if *oobURL == "" {
		*oobURL = "http://" + *oobAddr
	}
	oobSrv := oob.New(*oobURL, oobHub)
	go func() {
		log.Printf("Interlace OOB:    %s (callback base %s)", *oobAddr, *oobURL)
		if err := http.ListenAndServe(*oobAddr, oobSrv.Handler()); err != nil {
			log.Printf("oob listener stopped: %v", err)
		}
	}()

	sched := scheduler.New(filepath.Join(*dataDir, "schedule.json"), func(ctx context.Context) {
		log.Printf("scheduled scan starting")
		n, f := scanAllInScope(ctx, st, sc, rep, oobSrv, findHub, nil)
		log.Printf("scheduled scan done: %d endpoints, %d findings", n, f)
	})

	go serveAPI(*apiAddr, *proxyAddr, authority, st, h, findHub, rep, sc, oobSrv, oobHub, ic, interHub, processFlow, *insecure, mr, wsHub, sess, sched, macroStore, wsIc, wsInterHub)

	log.Printf("Interlace %s", version)
	log.Printf("Interlace UI:    http://%s", *apiAddr)
	log.Printf("Interlace proxy: http://%s", *proxyAddr)
	log.Printf("Root CA:         %s", filepath.Join(*dataDir, "ca", "interlace-root-ca.pem"))

	if *openUI {
		go openBrowser("http://" + *apiAddr)
	}

	if err := p.ListenAndServe(); err != nil {
		log.Fatalf("proxy: %v", err)
	}
}

// openBrowser launches the default browser at url (best-effort, Windows/mac/Linux).
func openBrowser(url string) {
	time.Sleep(600 * time.Millisecond) // let the listeners come up first
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

// summary is the lightweight row shape sent to the UI (no bodies).
type summary struct {
	ID          int64  `json:"id"`
	Time        string `json:"time"`
	Method      string `json:"method"`
	Scheme      string `json:"scheme"`
	Host        string `json:"host"`
	Path        string `json:"path"`
	Status      int    `json:"status"`
	ContentType string `json:"contentType"`
	Length      int    `json:"length"`
	DurationMs  int64  `json:"durationMs"`
	Error       string `json:"error,omitempty"`
}

func summarize(f *model.Flow) summary {
	length := f.RespLen
	if length == 0 {
		length = len(f.RespBody) // live flows carry the body directly
	}
	return summary{
		ID:          f.ID,
		Time:        f.Timestamp.Format("15:04:05"),
		Method:      f.Method,
		Scheme:      f.Scheme,
		Host:        f.Host,
		Path:        f.Path,
		Status:      f.StatusCode,
		ContentType: f.ContentType,
		Length:      length,
		DurationMs:  f.DurationMs,
		Error:       f.Error,
	}
}

func serveAPI(addr, proxyAddr string, authority *ca.CA, st *store.Store, h, findHub *hub.Hub, rep *repeater.Sender, sc *scope.Scope, oobSrv *oob.Server, oobHub *hub.Hub, ic *intercept.Interceptor, interHub *hub.Hub, processFlow func(*model.Flow), insecure bool, mr *matchreplace.Engine, wsHub *hub.Hub, sess *session.Session, sched *scheduler.Scheduler, macroStore *macro.Store, wsIc *wsintercept.Interceptor, wsInterHub *hub.Hub) {
	mux := http.NewServeMux()

	// WebSocket interception: state, toggle, resolve, live changes.
	mux.HandleFunc("/wsintercept", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"enabled": wsIc.Enabled(), "pending": wsIc.Pending()})
	})
	mux.HandleFunc("/wsintercept/toggle", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Enabled bool `json:"enabled"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		wsIc.SetEnabled(in.Enabled)
		writeJSON(w, map[string]bool{"enabled": wsIc.Enabled()})
	})
	mux.HandleFunc("/wsintercept/resolve", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ID      int64  `json:"id"`
			Action  string `json:"action"`
			Payload string `json:"payload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]bool{"ok": wsIc.Resolve(in.ID, in.Action, in.Payload)})
	})
	mux.HandleFunc("/wsintercept/events", func(w http.ResponseWriter, r *http.Request) {
		sseStream(w, r, wsInterHub)
	})

	// Login macro: save the ordered flow IDs, or replay them to get a session.
	mux.HandleFunc("/macro", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var ids []int64
			if err := json.NewDecoder(r.Body).Decode(&ids); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if err := macroStore.Set(ids); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		writeJSON(w, macroStore.Get())
	})
	mux.HandleFunc("/macro/replay", func(w http.ResponseWriter, r *http.Request) {
		ids := macroStore.Get()
		var steps []macro.Step
		for _, id := range ids {
			if f, _ := st.Get(id); f != nil {
				steps = append(steps, macro.Step{Scheme: f.Scheme, Host: authorityOf(f), Raw: flowToRaw(f)})
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		cookie, err := macro.Replay(ctx, steps, insecure)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if cookie != "" {
			// Merge the obtained Cookie into the session headers.
			hs := sess.Get()
			out := hs[:0]
			for _, h := range hs {
				if !strings.EqualFold(h.Name, "Cookie") {
					out = append(out, h)
				}
			}
			out = append(out, session.Header{Name: "Cookie", Value: cookie})
			_ = sess.Set(out)
		}
		writeJSON(w, map[string]any{"steps": len(steps), "cookie": cookie})
	})

	// Scan scheduling.
	mux.HandleFunc("/schedule", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var in struct {
				Enabled     bool `json:"enabled"`
				IntervalMin int  `json:"intervalMin"`
			}
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if err := sched.Set(in.Enabled, in.IntervalMin); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		writeJSON(w, sched.Status())
	})

	// Session headers (for authenticated scanning/repeater/crawl).
	mux.HandleFunc("/session", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var hs []session.Header
			if err := json.NewDecoder(r.Body).Decode(&hs); err != nil {
				http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
				return
			}
			if err := sess.Set(hs); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		writeJSON(w, sess.Get())
	})

	// WebSocket messages: list + live stream.
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		msgs, err := st.ListWS(1000)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, msgs)
	})
	mux.HandleFunc("/ws/events", func(w http.ResponseWriter, r *http.Request) {
		sseStream(w, r, wsHub)
	})
	// WebSocket Repeater: open a connection, send a message, return the reply.
	mux.HandleFunc("/ws/send", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Scheme  string `json:"scheme"`
			Host    string `json:"host"`
			Path    string `json:"path"`
			Message string `json:"message"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if in.Path == "" {
			in.Path = "/"
		}
		scheme := "ws"
		if in.Scheme == "wss" || in.Scheme == "https" {
			scheme = "wss"
		}
		dialer := websocket.Dialer{
			HandshakeTimeout: 10 * time.Second,
			TLSClientConfig:  &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec
		}
		c, _, err := dialer.Dial(scheme+"://"+in.Host+in.Path, nil)
		if err != nil {
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		defer c.Close()
		if err := c.WriteMessage(websocket.TextMessage, []byte(in.Message)); err != nil {
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, reply, err := c.ReadMessage()
		if err != nil {
			writeJSON(w, map[string]any{"sent": in.Message, "reply": "", "error": "no reply: " + err.Error()})
			return
		}
		writeJSON(w, map[string]any{"sent": in.Message, "reply": string(reply)})
	})

	// Match & Replace rules.
	mux.HandleFunc("/matchreplace", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var rules []matchreplace.Rule
			if err := json.NewDecoder(r.Body).Decode(&rules); err != nil {
				http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
				return
			}
			if err := mr.Set(rules); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		writeJSON(w, mr.Get())
	})

	// Content discovery: brute-force hidden paths on a scope-gated host.
	mux.HandleFunc("/discover", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Scheme string `json:"scheme"`
			Host   string `json:"host"`
			FlowID int64  `json:"flowId"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.FlowID != 0 {
			if f, _ := st.Get(in.FlowID); f != nil {
				in.Scheme, in.Host = f.Scheme, authorityOf(f)
			}
		}
		if in.Scheme == "" {
			in.Scheme = "https"
		}
		flusher, _ := w.(http.Flusher)
		w.Header().Set("Content-Type", "application/x-ndjson")
		enc := json.NewEncoder(w)
		if !sc.InScope(in.Host) {
			_ = enc.Encode(map[string]any{"done": true, "error": "host not in scope"})
			if flusher != nil {
				flusher.Flush()
			}
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
		defer cancel()
		var mu sync.Mutex
		found, _ := recon.ContentDiscovery(ctx, in.Scheme, in.Host, recon.Paths(), insecure,
			processFlow, sess, func(res recon.DiscoveryResult) {
				if !res.Found {
					return // only stream hits
				}
				mu.Lock()
				_ = enc.Encode(res)
				if flusher != nil {
					flusher.Flush()
				}
				mu.Unlock()
			}, 20)
		mu.Lock()
		_ = enc.Encode(map[string]any{"done": true, "found": found})
		if flusher != nil {
			flusher.Flush()
		}
		mu.Unlock()
	})

	// Parameter mining: discover unlinked parameters on a captured request.
	mux.HandleFunc("/parammine", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			FlowID int64 `json:"flowId"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		f, _ := st.Get(in.FlowID)
		if f == nil {
			http.Error(w, "flow not found", http.StatusNotFound)
			return
		}
		host := authorityOf(f)
		flusher, _ := w.(http.Flusher)
		w.Header().Set("Content-Type", "application/x-ndjson")
		enc := json.NewEncoder(w)
		if !sc.InScope(host) {
			_ = enc.Encode(map[string]any{"done": true, "error": "host not in scope"})
			if flusher != nil {
				flusher.Flush()
			}
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
		defer cancel()
		path := strings.Split(f.Path, "?")[0]
		var mu sync.Mutex
		found, _ := recon.ParamMine(ctx, f.Scheme, host, f.Method, path, f.ReqHeaders, recon.Params(),
			insecure, sess, func(res recon.ParamResult) {
				mu.Lock()
				_ = enc.Encode(res)
				if flusher != nil {
					flusher.Flush()
				}
				mu.Unlock()
			}, 12)
		mu.Lock()
		_ = enc.Encode(map[string]any{"done": true, "found": found})
		if flusher != nil {
			flusher.Flush()
		}
		mu.Unlock()
	})

	// Crawl: same-origin, scope-gated crawl feeding history + passive scan.
	mux.HandleFunc("/crawl", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var in struct {
			URL      string `json:"url"`
			FlowID   int64  `json:"flowId"`
			MaxPages int    `json:"maxPages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if in.FlowID != 0 {
			if f, _ := st.Get(in.FlowID); f != nil {
				in.URL = f.URL
			}
		}
		u, err := url.Parse(in.URL)
		if err != nil || u.Host == "" {
			http.Error(w, "invalid seed URL", http.StatusBadRequest)
			return
		}
		flusher, _ := w.(http.Flusher)
		w.Header().Set("Content-Type", "application/x-ndjson")
		if !sc.InScope(u.Hostname()) {
			_ = json.NewEncoder(w).Encode(map[string]any{"done": true, "pages": 0,
				"error": "host " + u.Hostname() + " is not in scope — add it under Scope before crawling"})
			if flusher != nil {
				flusher.Flush()
			}
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
		defer cancel()
		enc := json.NewEncoder(w)
		var mu sync.Mutex
		pages, runErr := crawler.Crawl(ctx, crawler.Seed{URL: in.URL}, insecure, sc.InScope,
			processFlow, func(pr crawler.Progress) {
				mu.Lock()
				_ = enc.Encode(pr)
				if flusher != nil {
					flusher.Flush()
				}
				mu.Unlock()
			}, in.MaxPages, sess)
		summary := map[string]any{"done": true, "pages": pages}
		if runErr != nil {
			summary["error"] = runErr.Error()
		}
		mu.Lock()
		_ = enc.Encode(summary)
		if flusher != nil {
			flusher.Flush()
		}
		mu.Unlock()
	})

	// Interception: state, toggle, resolve, live changes.
	mux.HandleFunc("/intercept", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"enabled": ic.Enabled(), "respEnabled": ic.RespEnabled(), "pending": ic.Pending()})
	})
	mux.HandleFunc("/intercept/toggle", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Enabled     *bool   `json:"enabled"`
			RespEnabled *bool   `json:"respEnabled"`
			Filter      *string `json:"filter"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.Enabled != nil {
			ic.SetEnabled(*in.Enabled)
		}
		if in.RespEnabled != nil {
			ic.SetRespEnabled(*in.RespEnabled)
		}
		if in.Filter != nil {
			ic.SetFilter(*in.Filter)
		}
		writeJSON(w, map[string]bool{"enabled": ic.Enabled(), "respEnabled": ic.RespEnabled()})
	})
	mux.HandleFunc("/intercept/resolve", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ID     int64  `json:"id"`
			Action string `json:"action"`
			Raw    string `json:"raw"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]bool{"ok": ic.Resolve(in.ID, in.Action, in.Raw)})
	})
	mux.HandleFunc("/intercept/events", func(w http.ResponseWriter, r *http.Request) {
		sseStream(w, r, interHub)
	})

	// Out-of-band: base URL + recent interactions + live stream.
	mux.HandleFunc("/oob", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"baseUrl": oobSrv.BaseURL(), "interactions": oobSrv.Recent(100)})
	})
	mux.HandleFunc("/oob/events", func(w http.ResponseWriter, r *http.Request) {
		sseStream(w, r, oobHub)
	})
	mux.HandleFunc("/oob/token", func(w http.ResponseWriter, r *http.Request) {
		token, url := oobSrv.NewToken()
		writeJSON(w, map[string]string{"token": token, "url": url})
	})

	// Scope: get/set the hosts permitted for active scanning.
	mux.HandleFunc("/scope", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var in struct {
				Include []string `json:"include"`
				Exclude []string `json:"exclude"`
			}
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
				return
			}
			if err := sc.Set(in.Include, in.Exclude); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		inc, exc := sc.Get()
		writeJSON(w, map[string][]string{"include": inc, "exclude": exc})
	})

	// Batch active scan: scans every in-scope captured flow. Streams NDJSON
	// progress ({scanned,total,host,path}) and persists/broadcasts findings.
	mux.HandleFunc("/scan/all", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		flusher, _ := w.(http.Flusher)
		w.Header().Set("Content-Type", "application/x-ndjson")
		enc := json.NewEncoder(w)
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Minute)
		defer cancel()
		scanned, found := scanAllInScope(ctx, st, sc, rep, oobSrv, findHub, func(p any) {
			_ = enc.Encode(p)
			if flusher != nil {
				flusher.Flush()
			}
		})
		_ = enc.Encode(map[string]any{"done": true, "scanned": scanned, "findings": found})
		if flusher != nil {
			flusher.Flush()
		}
	})

	// Active scan: scope-gated, streams NDJSON findings, persists + broadcasts.
	mux.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var in struct {
			FlowID int64  `json:"flowId"`
			Scheme string `json:"scheme"`
			Host   string `json:"host"`
			Raw    string `json:"raw"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		// Resolve target from a captured flow if given.
		if in.FlowID != 0 {
			f, err := st.Get(in.FlowID)
			if err != nil || f == nil {
				http.Error(w, "flow not found", http.StatusNotFound)
				return
			}
			in.Scheme, in.Host = f.Scheme, authorityOf(f)
			in.Raw = flowToRaw(f)
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")

		// SCOPE GUARDRAIL: refuse to send probes to out-of-scope hosts.
		if !sc.InScope(in.Host) {
			enc := json.NewEncoder(w)
			_ = enc.Encode(map[string]any{"done": true, "probes": 0,
				"error": "host " + in.Host + " is not in scope — add it under Scope before active scanning"})
			flusher.Flush()
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
		defer cancel()

		enc := json.NewEncoder(w)
		var mu sync.Mutex
		var found int
		probes, runErr := scanner.RunActive(ctx,
			scanner.Target{Scheme: in.Scheme, Host: in.Host, Raw: in.Raw}, rep, oobSrv,
			func(f scanner.Finding) {
				f.FlowID = in.FlowID
				f.Host = scanner.HostOf(in.Host)
				f.Time = time.Now()
				id, inserted, err := st.InsertFinding(&f)
				if err == nil && inserted {
					f.ID = id
					if msg, e := json.Marshal(f); e == nil {
						findHub.Broadcast(msg)
					}
				}
				mu.Lock()
				_ = enc.Encode(f)
				flusher.Flush()
				found++
				mu.Unlock()
			})
		summary := map[string]any{"done": true, "probes": probes, "findings": found}
		if runErr != nil {
			summary["error"] = runErr.Error()
		}
		mu.Lock()
		_ = enc.Encode(summary)
		flusher.Flush()
		mu.Unlock()
	})

	// Findings list.
	mux.HandleFunc("/findings", func(w http.ResponseWriter, r *http.Request) {
		fs, err := st.ListFindings()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, fs)
	})

	// Live findings stream (SSE).
	mux.HandleFunc("/findings/events", func(w http.ResponseWriter, r *http.Request) {
		sseStream(w, r, findHub)
	})

	// Repeater: send a hand-edited request and return the response.
	mux.HandleFunc("/repeater", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var in repeater.Request
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		writeJSON(w, rep.Send(ctx, in))
	})

	// Fuzzer: run an Intruder-style attack, streaming one NDJSON result per line.
	mux.HandleFunc("/fuzz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var cfg fuzzer.Config
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		// Scope guardrail: the fuzzer sends many requests; keep it in-scope.
		if !sc.InScope(cfg.Host) {
			_ = json.NewEncoder(w).Encode(map[string]any{"done": true, "total": 0,
				"error": "host " + cfg.Host + " is not in scope — add it under Scope before fuzzing"})
			flusher.Flush()
			return
		}
		w.Header().Set("Cache-Control", "no-cache")

		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()

		enc := json.NewEncoder(w)
		var mu sync.Mutex
		total, runErr := fuzzer.Run(ctx, cfg, rep, func(res fuzzer.Result) {
			mu.Lock()
			_ = enc.Encode(res)
			flusher.Flush()
			mu.Unlock()
		})
		summary := map[string]any{"done": true, "total": total}
		if runErr != nil {
			summary["error"] = runErr.Error()
		}
		mu.Lock()
		_ = enc.Encode(summary)
		flusher.Flush()
		mu.Unlock()
	})

	// Web UI.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		page, _ := webFS.ReadFile("web/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(page)
	})

	// Runtime config for the UI (proxy address to show in setup hints).
	mux.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"proxyAddr": proxyAddr})
	})

	// Download the root CA certificate for installation.
	mux.HandleFunc("/cert", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="interlace-root-ca.pem"`)
		_, _ = w.Write(authority.RootPEM())
	})

	// List captured flows (summaries).
	mux.HandleFunc("/flows", func(w http.ResponseWriter, r *http.Request) {
		opts := store.ListOpts{Host: r.URL.Query().Get("host")}
		if l := r.URL.Query().Get("limit"); l != "" {
			opts.Limit, _ = strconv.Atoi(l)
		}
		flows, err := st.List(opts)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		rows := make([]summary, 0, len(flows))
		for i := range flows {
			rows = append(rows, summarize(&flows[i]))
		}
		writeJSON(w, rows)
	})

	// Fetch a single flow with bodies (bodies are base64 in JSON). Compressed
	// response bodies are decompressed so the viewer shows readable text.
	mux.HandleFunc("/flow", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
		f, err := st.Get(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if f == nil {
			http.NotFound(w, r)
			return
		}
		decompressFlow(f)
		writeJSON(w, f)
	})

	// Clear all history.
	mux.HandleFunc("/clear", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		if err := st.Clear(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})

	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		n, _ := st.Count()
		fn, _ := st.CountFindings()
		writeJSON(w, map[string]int64{"flows": n, "findings": fn})
	})

	// Downloadable HTML security report (print to PDF from the browser).
	mux.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		findings, err := st.ListFindings()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		flows, _ := st.Count()
		counts := map[string]int{"high": 0, "medium": 0, "low": 0, "info": 0}
		for _, f := range findings {
			counts[f.Severity]++
		}
		switch r.URL.Query().Get("format") {
		case "json":
			if r.URL.Query().Get("dl") != "" {
				w.Header().Set("Content-Disposition", `attachment; filename="interlace-report.json"`)
			}
			writeJSON(w, map[string]any{
				"generated": time.Now().Format(time.RFC3339), "flows": flows,
				"counts": counts, "findings": findings,
			})
			return
		case "sarif":
			if r.URL.Query().Get("dl") != "" {
				w.Header().Set("Content-Disposition", `attachment; filename="interlace.sarif"`)
			}
			writeJSON(w, buildSARIF(findings))
			return
		}

		// Group findings by host and attach remediation guidance.
		type repFinding struct {
			scanner.Finding
			Remediation string
		}
		type hostGroup struct {
			Host     string
			Findings []repFinding
		}
		order := []string{}
		byHost := map[string][]repFinding{}
		for _, f := range findings {
			if _, ok := byHost[f.Host]; !ok {
				order = append(order, f.Host)
			}
			byHost[f.Host] = append(byHost[f.Host], repFinding{f, remediationFor(f.Check)})
		}
		var groups []hostGroup
		for _, h := range order {
			groups = append(groups, hostGroup{Host: h, Findings: byHost[h]})
		}

		data := struct {
			Generated string
			Flows     int64
			Counts    map[string]int
			Findings  []scanner.Finding
			Groups    []hostGroup
		}{time.Now().Format("2006-01-02 15:04 MST"), flows, counts, findings, groups}

		if r.URL.Query().Get("dl") != "" {
			w.Header().Set("Content-Disposition", `attachment; filename="interlace-report.html"`)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := reportTmpl.Execute(w, data); err != nil {
			log.Printf("report render: %v", err)
		}
	})

	// Server-Sent Events: live stream of newly captured flows.
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		sseStream(w, r, h)
	})

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Printf("api server stopped: %v", err)
	}
}

// sseStream subscribes to a hub and relays messages to the client as SSE until
// the client disconnects.
func sseStream(w http.ResponseWriter, r *http.Request, h *hub.Hub) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, unsubscribe := h.Subscribe()
	defer unsubscribe()

	fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	keepAlive := time.NewTicker(25 * time.Second)
	defer keepAlive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-keepAlive.C:
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// remediationFor returns short remediation guidance for a check.
func remediationFor(check string) string {
	switch check {
	case "missing-hsts":
		return "Add Strict-Transport-Security with a long max-age and includeSubDomains."
	case "missing-csp":
		return "Define a Content-Security-Policy restricting script/style/frame sources."
	case "missing-xfo":
		return "Set X-Frame-Options: DENY or a CSP frame-ancestors directive."
	case "missing-nosniff":
		return "Add X-Content-Type-Options: nosniff."
	case "missing-referrer-policy":
		return "Set Referrer-Policy (e.g. strict-origin-when-cross-origin)."
	case "cookie-no-secure", "cookie-no-httponly", "cookie-no-samesite":
		return "Set the Secure, HttpOnly and SameSite attributes on session cookies."
	case "cors-wildcard", "cors-wildcard-credentials", "cors-origin-reflection", "cors-null-origin":
		return "Restrict Access-Control-Allow-Origin to a trusted allowlist; never combine a reflected/wildcard origin with credentials."
	case "server-version", "x-powered-by":
		return "Remove or obfuscate version/technology headers."
	case "mixed-content":
		return "Serve all sub-resources over HTTPS."
	case "cacheable-sensitive":
		return "Add Cache-Control: no-store (and private) to authenticated responses."
	case "exposed-secret":
		return "Rotate the exposed credential immediately and remove secrets from responses/source."
	case "jwt-alg-none", "jwt-observed":
		return "Reject the \"none\" algorithm; verify signatures with a strong secret/key."
	case "sqli-error", "sqli-time", "sqli-boolean":
		return "Use parameterized queries / prepared statements; never concatenate input into SQL."
	case "reflected-xss":
		return "Context-encode output and apply a strict Content-Security-Policy."
	case "ssti":
		return "Never pass user input into template engines; use a sandbox or logic-less templates."
	case "path-traversal":
		return "Canonicalize and validate file paths against an allowlist; avoid user-controlled paths."
	case "cmdi":
		return "Avoid shelling out with user input; use safe APIs and strict allowlists."
	case "open-redirect":
		return "Validate redirect targets against an allowlist of internal URLs."
	case "blind-ssrf":
		return "Validate and allowlist outbound request destinations; block internal ranges and metadata endpoints."
	default:
		return "Review and remediate according to secure-coding guidance."
	}
}

// buildSARIF renders findings as a SARIF 2.1.0 log for CI / code-scanning.
func buildSARIF(findings []scanner.Finding) map[string]any {
	sarifLevel := func(sev string) string {
		switch sev {
		case scanner.High:
			return "error"
		case scanner.Medium:
			return "warning"
		default:
			return "note"
		}
	}
	rules := map[string]bool{}
	var ruleDefs []map[string]any
	var results []map[string]any
	for _, f := range findings {
		if !rules[f.Check] {
			rules[f.Check] = true
			ruleDefs = append(ruleDefs, map[string]any{
				"id": f.Check, "name": f.Title,
				"shortDescription": map[string]any{"text": f.Title},
			})
		}
		loc := f.URL
		if loc == "" {
			loc = "https://" + f.Host + "/"
		}
		results = append(results, map[string]any{
			"ruleId": f.Check, "level": sarifLevel(f.Severity),
			"message": map[string]any{"text": f.Detail + " (" + f.Evidence + ")"},
			"locations": []map[string]any{{
				"physicalLocation": map[string]any{
					"artifactLocation": map[string]any{"uri": loc},
				},
			}},
			"properties": map[string]any{"severity": f.Severity, "host": f.Host, "source": f.Source},
		})
	}
	return map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{{
			"tool": map[string]any{"driver": map[string]any{
				"name": "Interlace", "version": version, "rules": ruleDefs,
			}},
			"results": results,
		}},
	}
}

// scanAllInScope runs an active scan over every in-scope captured endpoint
// (deduplicated by host+path). emit, if non-nil, receives progress maps.
func scanAllInScope(ctx context.Context, st *store.Store, sc *scope.Scope, rep *repeater.Sender,
	oobSrv *oob.Server, findHub *hub.Hub, emit func(any)) (int, int) {

	flows, err := st.List(store.ListOpts{Limit: 1000})
	if err != nil {
		return 0, 0
	}
	seen := map[string]bool{}
	var targets []model.Flow
	for _, f := range flows {
		if !sc.InScope(f.Host) {
			continue
		}
		key := f.Host + "|" + strings.Split(f.Path, "?")[0]
		if seen[key] {
			continue
		}
		seen[key] = true
		targets = append(targets, f)
	}

	found := 0
	for i, t := range targets {
		if ctx.Err() != nil {
			break
		}
		full, _ := st.Get(t.ID)
		if full == nil {
			continue
		}
		_, _ = scanner.RunActive(ctx,
			scanner.Target{Scheme: full.Scheme, Host: authorityOf(full), Raw: flowToRaw(full)}, rep, oobSrv,
			func(f scanner.Finding) {
				f.FlowID = full.ID
				f.Host = scanner.HostOf(authorityOf(full))
				f.Time = time.Now()
				id, inserted, err := st.InsertFinding(&f)
				if err == nil && inserted {
					f.ID = id
					if msg, e := json.Marshal(f); e == nil {
						findHub.Broadcast(msg)
					}
					found++
				}
			})
		if emit != nil {
			emit(map[string]any{"scanned": i + 1, "total": len(targets), "host": t.Host, "path": strings.Split(t.Path, "?")[0], "findings": found})
		}
	}
	return len(targets), found
}

// authorityOf returns the host:port for a flow, preferring the full authority
// from the URL (which keeps the port) over the port-stripped Host field.
func authorityOf(f *model.Flow) string {
	if u, err := url.Parse(f.URL); err == nil && u.Host != "" {
		return u.Host
	}
	return f.Host
}

// decompressFlow decodes a gzip/deflate response body in place so the UI can
// display it as text, clearing the Content-Encoding header.
func decompressFlow(f *model.Flow) {
	if len(f.RespBody) == 0 {
		return
	}
	enc := strings.ToLower(f.RespHeaders.Get("Content-Encoding"))
	var out []byte
	switch enc {
	case "gzip":
		if gz, err := gzip.NewReader(bytes.NewReader(f.RespBody)); err == nil {
			out, _ = io.ReadAll(io.LimitReader(gz, 16<<20))
			gz.Close()
		}
	case "deflate":
		fr := flate.NewReader(bytes.NewReader(f.RespBody))
		out, _ = io.ReadAll(io.LimitReader(fr, 16<<20))
		fr.Close()
	default:
		return
	}
	if out != nil {
		f.RespBody = out
		f.RespHeaders.Del("Content-Encoding")
		f.RespHeaders.Set("Content-Length", strconv.Itoa(len(out)))
	}
}

// flowToRaw reconstructs a raw HTTP/1.1 request from a captured flow.
func flowToRaw(f *model.Flow) string {
	var b strings.Builder
	b.WriteString(f.Method + " " + f.Path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + authorityOf(f) + "\r\n")
	for name, vals := range f.ReqHeaders {
		if strings.EqualFold(name, "host") {
			continue
		}
		for _, v := range vals {
			b.WriteString(name + ": " + v + "\r\n")
		}
	}
	b.WriteString("\r\n")
	b.Write(f.ReqBody)
	return b.String()
}

func defaultDataDir() string {
	if wd, err := os.Getwd(); err == nil {
		return filepath.Join(wd, "interlace-data")
	}
	return "interlace-data"
}
