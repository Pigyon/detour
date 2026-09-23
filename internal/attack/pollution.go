package attack

import (
	"context"
	"net/url"
	"strings"

	"github.com/nedlir/detour/internal/model"
	"github.com/nedlir/detour/internal/payload"
)

// techniquePollution is a parameter sent twice, where the validator and the
// sink do not read the same copy.
//
// Every stack resolves a repeated query parameter differently. PHP and Go take
// the last, ASP.NET joins them with a comma, Python and Node take the first,
// and a proxy in front may reorder or drop one. An application that validates
// one copy and redirects using the other is open, and no single-value payload
// finds it: the trusted value has to be present at the same time as the
// attacker's, which is exactly what a one-parameter probe cannot express.
const techniquePollution = "OR-A16"

// pollutionOrders are the two arrangements worth sending. Which one works
// names which side of the stack disagreed.
var pollutionOrders = []struct {
	name    string
	trusted bool
}{
	{name: "trusted-first", trusted: true},
	{name: "attacker-first", trusted: false},
}

// attackPollution sends a redirect parameter twice, keeping the value the
// endpoint already had alongside the destination.
func (e *Engine) attackPollution(ctx context.Context, parsed *url.URL) []model.Finding {
	hits := []model.Finding{}
	query := parsed.Query()

	for _, name := range targetParams(query) {
		if isHostParam(name) {
			continue
		}

		current := query.Get(name)
		if current == "" {
			continue
		}

		if f, ok := e.pollutionAttempt(ctx, parsed, name, current); ok {
			hits = append(hits, f)
		}
	}

	return hits
}

// pollutionAttempt tries both orderings and requires the independent second
// destination to travel the same route.
func (e *Engine) pollutionAttempt(
	ctx context.Context, parsed *url.URL, name, current string,
) (model.Finding, bool) {
	for _, order := range pollutionOrders {
		probed := pollutedURL(parsed, name, current, "https://"+e.canary+"/", order.trusted)
		alt := pollutedURL(parsed, name, current, "https://"+AltCanary(e.canary)+"/", order.trusted)

		pair, found, status, err := e.readDest(ctx, probed, nil, e.canary)
		if err != nil || !found.reached(pair, e.canary) {
			continue
		}

		altPair, altFound, _, err := e.readDest(ctx, alt, nil, AltCanary(e.canary))
		if err != nil || !altFound.reached(altPair, AltCanary(e.canary)) {
			continue
		}

		pr := probe{
			source:   parsed.String(),
			probed:   probed,
			expanded: "https://" + e.canary + "/",
			param:    name,
			payload:  payload.Payload{Technique: techniquePollution, Mechanism: payload.MechHPP},
		}

		f := e.finding(pr, pair, found, status)
		f.TechniqueID = techniquePollution
		f.Mechanism = payload.MechHPP
		f.Evidence = append(f.Evidence,
			"pollution_order="+order.name,
			"kept_value="+current,
		)

		return f, true
	}

	return model.Finding{}, false
}

// pollutedURL writes the parameter twice, in the requested order.
//
// The query is assembled by hand because url.Values.Encode sorts keys and
// would collapse the ordering this technique turns on.
func pollutedURL(parsed *url.URL, name, trusted, attacker string, trustedFirst bool) string {
	first, second := attacker, trusted
	if trustedFirst {
		first, second = trusted, attacker
	}

	pairs := []string{}

	for existing := range strings.SplitSeq(parsed.RawQuery, "&") {
		key, _, _ := strings.Cut(existing, "=")
		if existing == "" || strings.EqualFold(key, name) {
			continue
		}

		pairs = append(pairs, existing)
	}

	pairs = append(pairs,
		url.QueryEscape(name)+"="+url.QueryEscape(first),
		url.QueryEscape(name)+"="+url.QueryEscape(second),
	)

	next := *parsed
	next.RawQuery = strings.Join(pairs, "&")

	return next.String()
}
