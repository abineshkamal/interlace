// Package login performs scripted username/password form logins so the
// automated pentest can scan as an authenticated user. It fetches the login
// page, locates the form containing the password field, submits it (carrying
// every hidden field, which preserves anti-CSRF / __VIEWSTATE tokens), and
// returns the resulting cookies as a Cookie header for the session store.
//
// It handles classic server-rendered login forms. JavaScript-built or
// multi-step (MFA/SSO) logins are out of scope — those need browser-assisted
// login, planned separately.
package login

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // TOTP (RFC 6238) is defined on HMAC-SHA1
	"crypto/tls"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// Config describes a form login to perform.
type Config struct {
	LoginURL     string
	Username     string
	Password     string
	UserField    string // optional; auto-detected if empty
	PassField    string // optional; auto-detected if empty
	SuccessRegex string // optional; must appear in the post-login response
	TOTPSecret   string // optional base32 secret for TOTP (RFC 6238) 2-step MFA
	OTPField     string // optional OTP field name; auto-detected if empty
	Insecure     bool
}

// Result reports the outcome of a login attempt.
type Result struct {
	OK           bool   `json:"ok"`
	CookieHeader string `json:"-"` // "a=1; b=2" for the session store
	Detail       string `json:"detail"`
	FinalURL     string `json:"finalUrl"`
}

type formInfo struct {
	action    string
	method    string
	values    url.Values
	userField string
	passField string
	otpField  string
}

// Perform executes the login and returns the captured session cookies.
func Perform(ctx context.Context, cfg Config) (Result, error) {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.Insecure}, //nolint:gosec // testing tool
		},
	}

	loginURL, err := url.Parse(cfg.LoginURL)
	if err != nil {
		return Result{}, fmt.Errorf("invalid login URL: %w", err)
	}

	// 1. Fetch the login page.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, cfg.LoginURL, nil)
	req.Header.Set("User-Agent", "Interlace-Pentest")
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("fetch login page: %w", err)
	}
	pageBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	resp.Body.Close()

	// 2. Find the login form.
	form, err := findLoginForm(string(pageBytes), cfg.UserField, cfg.PassField)
	if err != nil {
		return Result{OK: false, Detail: err.Error()}, nil
	}
	form.values.Set(form.userField, cfg.Username)
	form.values.Set(form.passField, cfg.Password)

	// 3. Resolve the form action and submit.
	actionURL := loginURL
	if form.action != "" {
		if a, err := url.Parse(form.action); err == nil {
			actionURL = loginURL.ResolveReference(a)
		}
	}
	method := strings.ToUpper(form.method)
	if method == "" {
		method = http.MethodPost
	}

	var postResp *http.Response
	if method == http.MethodGet {
		u := *actionURL
		u.RawQuery = form.values.Encode()
		r, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		r.Header.Set("User-Agent", "Interlace-Pentest")
		postResp, err = client.Do(r)
	} else {
		r, _ := http.NewRequestWithContext(ctx, http.MethodPost, actionURL.String(), strings.NewReader(form.values.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("User-Agent", "Interlace-Pentest")
		postResp, err = client.Do(r)
	}
	if err != nil {
		return Result{}, fmt.Errorf("submit login: %w", err)
	}
	finalBody, _ := io.ReadAll(io.LimitReader(postResp.Body, 4<<20))
	postResp.Body.Close()

	// 3b. Optional TOTP (RFC 6238) second step: if a secret is configured and the
	// post-credential page shows an OTP form, generate the code and submit it.
	mfaNote := ""
	if cfg.TOTPSecret != "" {
		if of, ok := findOTPForm(string(finalBody), cfg.OTPField); ok {
			code, cerr := totpCode(cfg.TOTPSecret, time.Now())
			if cerr != nil {
				mfaNote = " (MFA: bad TOTP secret: " + cerr.Error() + ")"
			} else {
				of.values.Set(of.otpField, code)
				cur := postResp.Request.URL
				otpAction := cur
				if of.action != "" {
					if a, aerr := url.Parse(of.action); aerr == nil {
						otpAction = cur.ResolveReference(a)
					}
				}
				om := strings.ToUpper(of.method)
				var r2 *http.Response
				var e2 error
				if om == http.MethodGet {
					u := *otpAction
					u.RawQuery = of.values.Encode()
					rq, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
					rq.Header.Set("User-Agent", "Interlace-Pentest")
					r2, e2 = client.Do(rq)
				} else {
					rq, _ := http.NewRequestWithContext(ctx, http.MethodPost, otpAction.String(), strings.NewReader(of.values.Encode()))
					rq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					rq.Header.Set("User-Agent", "Interlace-Pentest")
					r2, e2 = client.Do(rq)
				}
				if e2 == nil {
					finalBody, _ = io.ReadAll(io.LimitReader(r2.Body, 4<<20))
					r2.Body.Close()
					postResp = r2
					actionURL = otpAction
					mfaNote = " (MFA: TOTP submitted)"
				} else {
					mfaNote = " (MFA: OTP submit failed: " + e2.Error() + ")"
				}
			}
		} else {
			mfaNote = " (MFA: no OTP form detected after login)"
		}
	}

	// 4. Collect cookies for the target host.
	cookieHeader := cookieHeaderFor(jar, actionURL)

	// 5. Verify.
	res := Result{CookieHeader: cookieHeader, FinalURL: postResp.Request.URL.String()}
	switch {
	case cfg.SuccessRegex != "":
		re, reErr := regexp.Compile(cfg.SuccessRegex)
		if reErr != nil {
			return Result{OK: false, Detail: "invalid success regex: " + reErr.Error()}, nil
		}
		if re.Match(finalBody) {
			res.OK, res.Detail = true, "login confirmed (success pattern matched)"
		} else {
			res.OK, res.Detail = false, "success pattern not found after login"
		}
	case cookieHeader != "":
		// Heuristic: cookies were set and the response no longer shows a password field.
		if stillHasPasswordField(string(finalBody)) {
			res.OK, res.Detail = false, "a password field is still present — credentials may be wrong"
		} else {
			res.OK, res.Detail = true, "login likely succeeded (session cookie set)"
		}
	default:
		res.OK, res.Detail = false, "no session cookie was set — login did not succeed"
	}
	res.Detail += mfaNote
	return res, nil
}

// totpCode computes the RFC 6238 TOTP (6-digit, 30s step, SHA-1) for a base32
// secret at time t.
func totpCode(secret string, t time.Time) (string, error) {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		return "", err
	}
	counter := uint64(t.Unix()) / 30
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", code), nil
}

var otpNameRe = regexp.MustCompile(`(?i)(otp|mfa|2fa|passcode|one.?time|auth.?code|verif|token|code|pin)`)

// findOTPForm locates a one-time-code form (a form with an OTP-like field and no
// password field) in the post-credential page, for 2-step MFA.
func findOTPForm(htmlStr, otpField string) (formInfo, bool) {
	doc, err := html.Parse(strings.NewReader(htmlStr))
	if err != nil {
		return formInfo{}, false
	}
	var forms []*html.Node
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			forms = append(forms, n)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	for _, f := range forms {
		fi := formInfo{values: url.Values{}, method: "post"}
		fi.action = attr(f, "action")
		if m := attr(f, "method"); m != "" {
			fi.method = m
		}
		hasPass := false
		otp := ""
		var textFields []string
		var inputs func(*html.Node)
		inputs = func(n *html.Node) {
			if n.Type == html.ElementNode && (n.Data == "input" || n.Data == "select" || n.Data == "textarea") {
				name := attr(n, "name")
				typ := strings.ToLower(attr(n, "type"))
				if name != "" {
					fi.values.Set(name, attr(n, "value"))
					switch {
					case typ == "password":
						hasPass = true
					case otpField != "" && name == otpField:
						otp = name
					case otp == "" && otpField == "" && (typ == "text" || typ == "tel" || typ == "number" || typ == "") && otpNameRe.MatchString(name):
						otp = name
					}
					if typ == "text" || typ == "tel" || typ == "number" {
						textFields = append(textFields, name)
					}
				}
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				inputs(c)
			}
		}
		inputs(f)
		if hasPass {
			continue // still the credential form
		}
		if otp == "" && otpField == "" && len(textFields) == 1 {
			otp = textFields[0] // a single visible field — almost certainly the code
		}
		if otp != "" {
			fi.otpField = otp
			return fi, true
		}
	}
	return formInfo{}, false
}

// findLoginForm parses HTML and returns the form that contains a password input.
func findLoginForm(htmlStr, userField, passField string) (formInfo, error) {
	doc, err := html.Parse(strings.NewReader(htmlStr))
	if err != nil {
		return formInfo{}, fmt.Errorf("parse HTML: %w", err)
	}
	var forms []*html.Node
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			forms = append(forms, n)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	for _, f := range forms {
		fi := formInfo{values: url.Values{}, method: "post"}
		fi.action = attr(f, "action")
		if m := attr(f, "method"); m != "" {
			fi.method = m
		}
		var lastTextField string
		var foundPass string
		var inputs func(*html.Node)
		inputs = func(n *html.Node) {
			if n.Type == html.ElementNode && (n.Data == "input" || n.Data == "select" || n.Data == "textarea") {
				name := attr(n, "name")
				typ := strings.ToLower(attr(n, "type"))
				val := attr(n, "value")
				if name != "" {
					fi.values.Set(name, val)
					switch typ {
					case "password":
						foundPass = name
					case "text", "email", "tel", "":
						if lastTextField == "" || typ == "email" {
							lastTextField = name
						}
					}
				}
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				inputs(c)
			}
		}
		inputs(f)

		if passField != "" {
			foundPass = passField
		}
		if foundPass == "" {
			continue // not a login form
		}
		fi.passField = foundPass
		fi.userField = userField
		if fi.userField == "" {
			fi.userField = lastTextField
		}
		if fi.userField == "" {
			return formInfo{}, fmt.Errorf("found a password field but no username field — set the field name explicitly")
		}
		return fi, nil
	}
	return formInfo{}, fmt.Errorf("no login form (with a password field) found on the page")
}

// Form is a discovered HTML form with placeholder values filled in, ready to be
// submitted so a scanner can exercise its parameters.
type Form struct {
	Action      string     // resolved absolute URL
	Method      string     // "GET" or "POST"
	Values      url.Values // field name -> placeholder value
	HasPassword bool
}

// ExtractForms parses every <form> in htmlStr, resolves its action against
// baseURL, and fills each field with a type-appropriate placeholder value (so
// hidden tokens are preserved and injectable fields get benign test input).
func ExtractForms(htmlStr, baseURL string) []Form {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	doc, err := html.Parse(strings.NewReader(htmlStr))
	if err != nil {
		return nil
	}
	var out []Form
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			out = append(out, buildForm(n, base))
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return out
}

func buildForm(f *html.Node, base *url.URL) Form {
	form := Form{Method: "GET", Values: url.Values{}}
	if m := strings.ToUpper(attr(f, "method")); m == "POST" {
		form.Method = "POST"
	}
	action := attr(f, "action")
	if a, err := url.Parse(action); err == nil {
		form.Action = base.ResolveReference(a).String()
	} else {
		form.Action = base.String()
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && (n.Data == "input" || n.Data == "select" || n.Data == "textarea") {
			name := attr(n, "name")
			if name != "" {
				typ := strings.ToLower(attr(n, "type"))
				form.Values.Set(name, placeholder(typ, attr(n, "value")))
				if typ == "password" {
					form.HasPassword = true
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(f)
	return form
}

// placeholder returns a benign test value for a form field by type, keeping any
// existing value for hidden/preset fields.
func placeholder(typ, existing string) string {
	switch typ {
	case "hidden", "submit", "button":
		return existing
	case "email":
		return "test@example.com"
	case "number", "tel":
		return "1"
	case "password":
		return "Passw0rd!1"
	case "checkbox", "radio":
		if existing != "" {
			return existing
		}
		return "on"
	default:
		if existing != "" {
			return existing
		}
		return "test"
	}
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}

func cookieHeaderFor(jar *cookiejar.Jar, u *url.URL) string {
	var parts []string
	for _, c := range jar.Cookies(u) {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

var passwordInputRe = regexp.MustCompile(`(?i)<input[^>]*type=["']?password`)

func stillHasPasswordField(body string) bool { return passwordInputRe.MatchString(body) }
