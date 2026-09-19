package lab_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/nedlir/detour/internal/lab"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const attacker = "https://evil.example/"

func TestClassAShapes(t *testing.T) {
	t.Parallel()

	srv := newLabServer(t)
	client := noFollow(t, srv)

	tests := []struct {
		name       string
		path       string
		wantStatus int
		wantLoc    string
		locs       int
	}{
		{
			name:       "OR-A01 userinfo",
			path:       "/a01?url=" + url.QueryEscape("https://"+lab.AllowedHost+"@evil.example/"),
			wantStatus: http.StatusFound,
			wantLoc:    "https://" + lab.AllowedHost + "@evil.example/",
		},
		{
			name:       "OR-A01 rejects bare attacker",
			path:       "/a01?url=" + url.QueryEscape(attacker),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "OR-A02 stuffed userinfo",
			path:       "/a02?url=" + url.QueryEscape("https://"+lab.AllowedHost+":@evil.example/"),
			wantStatus: http.StatusFound,
			wantLoc:    "https://" + lab.AllowedHost + ":@evil.example/",
		},
		{
			name:       "OR-A02 rejects plain userinfo",
			path:       "/a02?url=" + url.QueryEscape("https://"+lab.AllowedHost+"@evil.example/"),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "OR-A03 backslash relative",
			path:       "/a03?url=" + url.QueryEscape("/\\evil.example/"),
			wantStatus: http.StatusFound,
			wantLoc:    "/\\evil.example/",
		},
		{
			name:       "OR-A05 ideographic full stop",
			path:       "/a05?url=" + url.QueryEscape("https://"+lab.AllowedHost+"\u3002evil.example/"),
			wantStatus: http.StatusFound,
		},
		{
			name:       "OR-A06 tab prefix",
			path:       "/a06?url=" + url.QueryEscape("\t//evil.example/"),
			wantStatus: http.StatusFound,
		},
		{
			name:       "OR-A07 protocol relative",
			path:       "/a07?url=" + url.QueryEscape("//evil.example/"),
			wantStatus: http.StatusFound,
			wantLoc:    "//evil.example/",
		},
		{
			name:       "OR-A08 contains in query",
			path:       "/a08?url=" + url.QueryEscape(attacker+"?"+lab.AllowedHost),
			wantStatus: http.StatusFound,
		},
		{
			name:       "OR-A09 prefix host",
			path:       "/a09?url=" + url.QueryEscape("https://"+lab.AllowedHost+".evil.example/"),
			wantStatus: http.StatusFound,
		},
		{
			name:       "OR-A10 traversal redirect_uri",
			path:       "/a10?redirect_uri=" + url.QueryEscape("https://"+lab.AllowedHost+"/app/..;/evil"),
			wantStatus: http.StatusFound,
		},
		{
			name:       "OR-A12 nul truncation",
			path:       "/a12?url=" + url.QueryEscape("https://"+lab.AllowedHost+"%00@evil.example/"),
			wantStatus: http.StatusFound,
		},
		{
			name:       "OR-A13 endswith path",
			path:       "/a13?url=" + url.QueryEscape("http://evil.example/www."+lab.AllowedHost),
			wantStatus: http.StatusFound,
		},
		{
			name:       "OR-A14 malformed scheme",
			path:       "/a14?url=" + url.QueryEscape("https:evil.example"),
			wantStatus: http.StatusFound,
			wantLoc:    "https:evil.example",
		},
		{
			name:       "OR-A15 decimal loopback",
			path:       "/a15?url=" + url.QueryEscape("http://2130706433/"),
			wantStatus: http.StatusFound,
			wantLoc:    "http://2130706433/",
		},
		{
			name:       "OR-A15 blocks dotted loopback",
			path:       "/a15?url=" + url.QueryEscape("http://127.0.0.1/"),
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			res := doGet(t, client, srv.URL+tt.path)
			require.Equal(t, tt.wantStatus, res.Status)

			if tt.wantLoc != "" {
				assert.Equal(t, tt.wantLoc, res.Header.Get("Location"))
			}
		})
	}
}

func TestA04SpringBracket(t *testing.T) {
	t.Parallel()

	raw := "https://evil.example[@" + lab.AllowedHost + "/"
	rec := servePath(t, "/a04?url="+url.QueryEscape(raw))
	require.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, raw, rec.Header().Get("Location"))
}

func TestA11CRLFInjectsSecondLocation(t *testing.T) {
	t.Parallel()

	rec := servePath(t, "/a11/%0d%0aLocation:%20https://evil.example/")
	require.Equal(t, http.StatusFound, rec.Code)

	locs := rec.Header().Values("Location")
	require.GreaterOrEqual(t, len(locs), 2)
	assert.Equal(t, "/safe", locs[0])
	assert.Contains(t, locs[1], "evil.example")
}
