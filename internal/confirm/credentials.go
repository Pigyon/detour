package confirm

import (
	"strings"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// headerMap returns the extra headers to attach, and only when the target
// itself is in scope.
//
// Chrome applies extra headers session-wide, so scoping them at the browser
// level is not possible. Two things keep credentials in bounds: this check,
// and the interception layer, which aborts every off-scope request before it
// leaves the browser, so a header can never accompany one.
func (c *Confirmer) headerMap(target string) network.Headers {
	if len(c.opts.Headers) == 0 || !c.inScope(target) {
		return nil
	}

	out := network.Headers{}

	for name, values := range c.opts.Headers {
		if len(values) > 0 {
			out[name] = values[0]
		}
	}

	return out
}

// cookieActions sets the operator's cookies for in-scope hosts only. A cookie
// with no domain is bound to the target host rather than left to float.
func (c *Confirmer) cookieActions(target string) chromedp.Action {
	if len(c.opts.Cookies) == 0 {
		return nil
	}

	host := hostOf(target)
	if host == "" {
		return nil
	}

	params := []*network.CookieParam{}

	for _, cookie := range c.opts.Cookies {
		domain := strings.TrimPrefix(strings.ToLower(cookie.Domain), ".")
		if domain == "" {
			domain = host
		}

		if !c.allows(domain) {
			continue
		}

		path := cookie.Path
		if path == "" {
			path = "/"
		}

		params = append(params, &network.CookieParam{
			Name:   cookie.Name,
			Value:  cookie.Value,
			Domain: domain,
			Path:   path,
		})
	}

	if len(params) == 0 {
		return nil
	}

	return network.SetCookies(params)
}

func (c *Confirmer) inScope(rawURL string) bool {
	return c.allows(hostOf(rawURL))
}

// allows applies the scope guard, and never lets the canary through.
func (c *Confirmer) allows(host string) bool {
	if host == "" {
		return false
	}

	canary := normalizeHost(c.opts.Canary)
	if canary != "" && (host == canary || strings.HasSuffix(host, "."+canary)) {
		return false
	}

	if c.guard == nil {
		return true
	}

	return c.guard.Allows(host)
}
