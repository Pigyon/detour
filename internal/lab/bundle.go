package lab

import "net/http"

// registerBundles mounts the client-side bundle fixtures. These exist so the
// JS analysis has something with the shape of a real application: a guard
// function, an allowlist, and a navigation that depends on both.
func registerBundles(mux *http.ServeMux) {
	mux.HandleFunc("GET /app/signin", handleSigninPage)
	mux.HandleFunc("GET /static/app.js", handleLooseBundle)
	mux.HandleFunc("GET /decoy/guarded", handleGuardedPage)
	mux.HandleFunc("GET /static/safe.js", handleSafeBundle)
}

func handleSigninPage(w http.ResponseWriter, _ *http.Request) {
	writeHTML(w, `<!doctype html><title>sign in</title><script src="/static/app.js"></script>`+"\n")
}

// looseBundle guards its navigation, but the guard matches the allowlist as a
// suffix, never restricts the scheme, and never looks at userinfo.
const looseBundle = `
const safeDomains = ["allowed.lab", "cdn.allowed.lab"];

function isTrusted(raw) {
  let u;
  try { u = new URL(raw, location.href) } catch (e) { return false }
  return safeDomains.some(d => u.hostname.endsWith(d));
}

function resume(params) {
  const backUrl = params.get("backUrl");
  const dest = isTrusted(backUrl) ? backUrl : "/account";
  location.href = dest;
}

resume(new URLSearchParams(location.search));
`

func handleLooseBundle(w http.ResponseWriter, _ *http.Request) {
	writeJS(w, looseBundle)
}

func handleGuardedPage(w http.ResponseWriter, _ *http.Request) {
	writeHTML(w, `<!doctype html><title>guarded</title><script src="/static/safe.js"></script>`+"\n")
}

// safeBundle is the decoy: exact hostname equality, https only, userinfo and
// javascript blocked. The analysis must produce no candidate verdicts for it.
const safeBundle = `
const allowed = ["allowed.lab"];

function isSafe(raw) {
  if (!raw) return false;
  if (/^javascript:/i.test(raw)) return false;
  let u;
  try { u = new URL(raw) } catch (e) { return false }
  if (u.protocol !== "https:") return false;
  if (u.username || u.password) return false;
  return allowed.some(d => u.hostname === d);
}

function go(next) {
  if (isSafe(next)) { location.assign(next) }
}

go(new URLSearchParams(location.search).get("next"));
`

func handleSafeBundle(w http.ResponseWriter, _ *http.Request) {
	writeJS(w, safeBundle)
}
