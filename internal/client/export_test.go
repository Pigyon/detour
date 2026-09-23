package client

// RateFor exposes the per-host limit so a test can assert what the adaptive
// throttle did. It is test-only on purpose: nothing in the tool should be
// making decisions from another host's limiter.
func (c *Client) RateFor(host string) float64 {
	return float64(c.limiterFor(host).Limit())
}
