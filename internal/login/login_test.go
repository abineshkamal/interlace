package login

import "testing"

const loginPage = `<html><body>
<form action="/doLogin" method="post">
  <input type="hidden" name="csrf" value="abc123">
  <input type="text" name="uid" value="">
  <input type="password" name="passw">
  <button type="submit">Login</button>
</form></body></html>`

func TestFindLoginForm(t *testing.T) {
	f, err := findLoginForm(loginPage, "", "")
	if err != nil {
		t.Fatalf("findLoginForm: %v", err)
	}
	if f.passField != "passw" {
		t.Errorf("password field = %q, want passw", f.passField)
	}
	if f.userField != "uid" {
		t.Errorf("username field = %q, want uid", f.userField)
	}
	if f.action != "/doLogin" || f.method != "post" {
		t.Errorf("action/method = %q/%q", f.action, f.method)
	}
	if f.values.Get("csrf") != "abc123" {
		t.Errorf("hidden csrf token not preserved: %q", f.values.Get("csrf"))
	}
}

func TestFindLoginFormNone(t *testing.T) {
	if _, err := findLoginForm(`<form><input name="q"></form>`, "", ""); err == nil {
		t.Error("expected an error for a form with no password field")
	}
}

func TestExtractForms(t *testing.T) {
	html := `<form action="search.jsp" method="get"><input name="query"></form>
	         <form action="/sendFeedback" method="post"><input type="hidden" name="t" value="9"><input name="comments"></form>`
	forms := ExtractForms(html, "http://site.test/index.jsp")
	if len(forms) != 2 {
		t.Fatalf("expected 2 forms, got %d", len(forms))
	}
	// GET form: relative action resolved, injectable field has a placeholder.
	if forms[0].Action != "http://site.test/search.jsp" || forms[0].Method != "GET" {
		t.Errorf("form0 action/method = %q/%q", forms[0].Action, forms[0].Method)
	}
	if forms[0].Values.Get("query") != "test" {
		t.Errorf("form0 placeholder = %q, want test", forms[0].Values.Get("query"))
	}
	// POST form: hidden value preserved, action resolved from root.
	if forms[1].Action != "http://site.test/sendFeedback" || forms[1].Method != "POST" {
		t.Errorf("form1 action/method = %q/%q", forms[1].Action, forms[1].Method)
	}
	if forms[1].Values.Get("t") != "9" {
		t.Errorf("form1 hidden value not preserved: %q", forms[1].Values.Get("t"))
	}
}
