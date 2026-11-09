// Package browser captures page screenshots for vulnerability evidence by
// driving an installed Chromium-family browser (Microsoft Edge or Google
// Chrome) in headless mode. It shells out to the browser's one-shot
// --screenshot flag, so it needs no Go dependency and bundles no Chromium.
//
// v1 renders in a fresh, anonymous browser context (no session cookies), so
// authenticated pages screenshot as logged-out. Injecting the captured session
// requires the Chrome DevTools Protocol and is planned for a later round.
package browser

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"
)

// candidatePaths lists where Edge/Chrome usually live on Windows, plus bare
// names resolved via PATH for other platforms.
func candidatePaths() []string {
	if runtime.GOOS == "windows" {
		pf := os.Getenv("ProgramFiles")
		pfx86 := os.Getenv("ProgramFiles(x86)")
		return []string{
			filepath.Join(pfx86, `Microsoft\Edge\Application\msedge.exe`),
			filepath.Join(pf, `Microsoft\Edge\Application\msedge.exe`),
			filepath.Join(pf, `Google\Chrome\Application\chrome.exe`),
			filepath.Join(pfx86, `Google\Chrome\Application\chrome.exe`),
		}
	}
	return []string{"google-chrome", "chromium", "chromium-browser", "chrome", "microsoft-edge"}
}

// Find returns the path to an installed browser, honoring the INTERLACE_BROWSER
// override, or "" if none is found.
func Find() string {
	if env := os.Getenv("INTERLACE_BROWSER"); env != "" {
		if _, err := os.Stat(env); err == nil {
			return env
		}
	}
	for _, p := range candidatePaths() {
		if filepath.IsAbs(p) {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		} else if resolved, err := exec.LookPath(p); err == nil {
			return resolved
		}
	}
	return ""
}

// Available reports whether a usable browser is installed.
func Available() bool { return Find() != "" }

var shotSeq int64

// Screenshot renders url in headless mode and returns the PNG bytes. workDir is
// a writable directory (on a drive with space) for the temp profile and output
// file. cookieHeader is accepted for forward compatibility but unused in v1.
func Screenshot(ctx context.Context, url, workDir, cookieHeader string) ([]byte, error) {
	bin := Find()
	if bin == "" {
		return nil, fmt.Errorf("no headless browser (Edge/Chrome) found")
	}
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return nil, fmt.Errorf("screenshot workdir: %w", err)
	}
	n := atomic.AddInt64(&shotSeq, 1)
	stamp := strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + strconv.FormatInt(n, 10)
	outPath := filepath.Join(workDir, "shot-"+stamp+".png")
	profile := filepath.Join(workDir, "profile-"+stamp)
	defer os.Remove(outPath)
	defer os.RemoveAll(profile)

	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	args := []string{
		"--headless=new",
		"--disable-gpu",
		"--no-sandbox",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-extensions",
		"--hide-scrollbars",
		"--window-size=1280,900",
		"--virtual-time-budget=5000",
		"--user-data-dir=" + profile,
		"--screenshot=" + outPath,
		url,
	}
	cmd := exec.CommandContext(cctx, bin, args...)
	// Best-effort: ignore non-zero exit (some builds exit 21 but still write the file).
	_ = cmd.Run()

	png, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("browser produced no screenshot (url may be unreachable)")
	}
	if len(png) == 0 {
		return nil, fmt.Errorf("browser produced an empty screenshot")
	}
	return png, nil
}
