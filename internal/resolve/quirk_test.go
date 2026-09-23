package resolve_test

import (
	"testing"

	"github.com/nedlir/detour/internal/resolve"
	"github.com/stretchr/testify/assert"
)

const (
	canaryHost  = "canary.invalid"
	allowedHost = "allowed.example"
	bracketLoc  = "https://" + canaryHost + "[@" + allowedHost + "/"
)

func TestQuirkHosts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		loc  string
		want []string
	}{
		{
			name: "spring bracket terminates the userinfo early",
			loc:  bracketLoc,
			want: []string{canaryHost, allowedHost},
		},
		{
			name: "stuffed port and backslash",
			loc:  `https://` + allowedHost + `:443:\@@` + canaryHost + `/`,
			want: []string{canaryHost, allowedHost},
		},
		{
			name: "raw space before the delimiter",
			loc:  "https://" + allowedHost + " &@" + canaryHost + "/",
			want: []string{canaryHost, allowedHost},
		},
		{
			name: "a url net/url accepts has no disagreement to report",
			loc:  "https://" + allowedHost + ":@" + canaryHost + "/",
			want: nil,
		},
		{
			name: "relative reference is not an authority",
			loc:  "/redirect?next=x",
			want: nil,
		},
		{
			name: "scheme with an empty authority",
			loc:  "https://",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, resolve.QuirkHosts(tt.loc))
		})
	}
}

func TestHitsCanaryQuirk(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		loc    string
		canary string
		want   bool
	}{
		{
			name:   "bracket form reaches the canary",
			loc:    bracketLoc,
			canary: canaryHost,
			want:   true,
		},
		{
			name:   "second canary travels the same route",
			loc:    "https://canary2.invalid[@" + allowedHost + "/",
			canary: "canary2.invalid",
			want:   true,
		},
		{
			name:   "unparseable but never reaches the canary",
			loc:    "https://one.example[@two.example/",
			canary: canaryHost,
			want:   false,
		},
		{
			name:   "empty canary matches nothing",
			loc:    bracketLoc,
			canary: "",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, resolve.HitsCanaryQuirk(tt.loc, tt.canary))
		})
	}
}

// FuzzQuirkHosts pushes hostile authorities through the lenient reader. It
// runs on strings net/url rejects, which is exactly where a parser is least
// exercised, so it must not panic and must stay bounded.
func FuzzQuirkHosts(f *testing.F) {
	for _, seed := range []string{
		bracketLoc,
		`https://a:443:\@@b/`,
		"https://@@@@@@@@/",
		"https://[[[[@@",
		"http://",
		"//no-scheme",
		"https://a b c/",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, loc string) {
		hosts := resolve.QuirkHosts(loc)

		assert.LessOrEqual(t, len(hosts), 8, "extraction must stay bounded")

		seen := map[string]struct{}{}

		for _, host := range hosts {
			assert.NotEmpty(t, host, "an empty host is never a candidate")

			_, dup := seen[host]
			assert.False(t, dup, "hosts must be deduplicated")

			seen[host] = struct{}{}
		}
	})
}
