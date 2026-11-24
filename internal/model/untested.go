package model

// BlockedProbe is one request a WAF or edge refused before the application
// ever judged the payload.
//
// It is not a miss. A miss says the endpoint saw the destination and kept the
// browser home; a block page says nothing about the endpoint at all, so the
// probe stays untested and is reported as such.
type BlockedProbe struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	// Vendor names the block page detour recognized ("cloudflare",
	// "akamai", ...), or "unknown" for a refusal the source's own baseline
	// did not produce.
	Vendor string `json:"vendor"`
}

// AuthWall is a source that answered its first request with a login wall, so
// its payloads were not sent anonymously.
type AuthWall struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	// Reason says which wall it was: "status" for a 401 or 407, "login
	// redirect" for a redirect to a sign-in page.
	Reason string `json:"reason"`
	// Location is where a login redirect pointed, empty otherwise.
	Location string `json:"location,omitempty"`
}
