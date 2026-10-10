package client

import "time"

// Exported for tests only: the real constants backing the adaptive rate
// limiter's pacing, so an external test can assert against them instead of
// duplicating magic numbers that would silently drift from the real values.
const (
	MinRate         = minRate
	SlowCooldown    = slowCooldown
	RecoverCooldown = recoverCooldown
)

// RateFor exposes the per-host limit so a test can assert what the adaptive
// throttle did. It is test-only on purpose: nothing in the tool should be
// making decisions from another host's limiter.
func (c *Client) RateFor(host string) float64 {
	return float64(c.limiterFor(host).limiter.Limit())
}

// HasGivenUpOn exposes whether a host has been given up on.
func (c *Client) HasGivenUpOn(host string) bool {
	return c.limiterFor(host).hasGivenUp()
}

// BackdateCooldowns pushes a host's cooldown timestamps into the past, so a
// test can exercise slowCooldown and recoverCooldown without sleeping
// real wall-clock time for each one.
func (c *Client) BackdateCooldowns(host string, by time.Duration) {
	h := c.limiterFor(host)

	h.mu.Lock()
	defer h.mu.Unlock()

	h.lastSlow = h.lastSlow.Add(-by)
	h.lastRecover = h.lastRecover.Add(-by)
}

// ForceSlow and ForceRecover drive a host's adaptive state directly, the way
// repeated pushback or repeated success would over a real run, without going
// through an actual request and the real rate.Limiter.Wait it would block on
// once the rate has collapsed. Each call backdates the cooldown first, so a
// test can build up floorPushbacks or walk the rate back up in a tight loop.
func (c *Client) ForceSlow(host string) {
	h := c.limiterFor(host)

	h.mu.Lock()
	h.lastSlow = h.lastSlow.Add(-slowCooldown)
	h.mu.Unlock()

	h.slow(time.Now())
}

func (c *Client) ForceRecover(host string) {
	h := c.limiterFor(host)

	h.mu.Lock()
	h.lastRecover = h.lastRecover.Add(-recoverCooldown)
	h.mu.Unlock()

	h.recover(time.Now())
}
