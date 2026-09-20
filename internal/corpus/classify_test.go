package corpus_test

import (
	"testing"

	"github.com/nedlir/detour/internal/corpus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Vendors and URLs shared across the corpus cases.
const (
	vendorSendGrid  = "sendgrid"
	vendorEngageLab = "engagelab"
	urlGoWithURL    = "https://a.lab/go?url=x"
)

func TestClassify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      string
		wantKinds  []corpus.Kind
		wantParams []string
		wantVendor string
		keep       bool
	}{
		{
			name:       "redirect shaped parameter name",
			input:      "https://a.lab/go?next=/account",
			wantKinds:  []corpus.Kind{corpus.KindParamName},
			wantParams: []string{"next"},
			keep:       true,
		},
		{
			name:       "value that is already a url",
			input:      "https://a.lab/page?image=https://cdn.a.lab/x.png",
			wantKinds:  []corpus.Kind{corpus.KindParamValue},
			wantParams: []string{"image"},
			keep:       true,
		},
		{
			name:       "percent encoded value counts",
			input:      "https://a.lab/page?q=https%3A%2F%2Fb.lab%2F",
			wantKinds:  []corpus.Kind{corpus.KindParamValue},
			wantParams: []string{"q"},
			keep:       true,
		},
		{
			name:       "protocol relative value counts",
			input:      "https://a.lab/page?q=//b.lab/",
			wantKinds:  []corpus.Kind{corpus.KindParamValue},
			wantParams: []string{"q"},
			keep:       true,
		},
		{
			name:       "name and value together",
			input:      "https://a.lab/go?url=https://b.lab/",
			wantKinds:  []corpus.Kind{corpus.KindParamName, corpus.KindParamValue},
			wantParams: []string{"url"},
			keep:       true,
		},
		{
			name:      "opaque path segment",
			input:     "https://a.lab/t/eJxLyU9OLcpMzFEoLsnMS1cAAFnnBJk",
			wantKinds: []corpus.Kind{corpus.KindPath},
			keep:      true,
		},
		{
			name:       "vendor click wrapper",
			input:      "https://trace.a.lab/track/click2/eJxLyU9OLcpMzFEoLsnMS1cAAFnnBJk.html",
			wantKinds:  []corpus.Kind{corpus.KindPath, corpus.KindVendorSig},
			wantVendor: vendorEngageLab,
			keep:       true,
		},
		{
			name:       "sendgrid wrapper by path and param",
			input:      "https://mail.a.lab/ls/click?upn=eyJ1cmwiOiJodHRwczovL2EuYi8ifQ",
			wantKinds:  []corpus.Kind{corpus.KindVendorSig},
			wantVendor: vendorSendGrid,
			keep:       true,
		},
		{name: "plain page is not interesting", input: "https://a.lab/about", keep: false},
		{name: "ordinary pagination", input: "https://a.lab/list?page=2", keep: false},
		{name: "static asset", input: "https://a.lab/app.css", keep: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			entry, ok := corpus.Classify(tt.input)
			require.Equal(t, tt.keep, ok)

			if !tt.keep {
				return
			}

			assert.Equal(t, tt.wantKinds, entry.Kinds)
			assert.Equal(t, tt.wantVendor, entry.Vendor)

			if tt.wantParams != nil {
				assert.Equal(t, tt.wantParams, entry.Params)
			}
		})
	}
}

func TestMatchVendor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "engagelab path on a customer host", input: "https://trace.customer.com/track/click2/abc", want: vendorEngageLab},
		{name: "sendgrid own host", input: "https://ct.sendgrid.net/ls/click?upn=x", want: vendorSendGrid},
		{name: "sendgrid path on a customer host", input: "https://mail.customer.com/ls/click?upn=x", want: vendorSendGrid},
		{name: "braze", input: "https://customer.com/api/v3/click?x=1", want: "braze"},
		{name: "iterable", input: "https://links.customer.com/a/click?x=1", want: "iterable"},
		{name: "not a wrapper", input: "https://customer.com/go?url=x", want: ""},
		{name: "path prefix without required param", input: "https://customer.com/ls/click", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := corpus.MatchVendor(tt.input)
			assert.Equal(t, tt.want != "", ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestMatchCNAME is the surface stage's priority signal: a customer subdomain
// delegated to an ESP runs that vendor's wrapper on a first-party domain.
func TestMatchCNAME(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		cname string
		want  string
	}{
		{name: vendorSendGrid, cname: "sendgrid.net", want: vendorSendGrid},
		{name: "sendgrid subdomain", cname: "u123.wl.sendgrid.net", want: vendorSendGrid},
		{name: "trailing dot tolerated", cname: "u123.wl.sendgrid.net.", want: vendorSendGrid},
		{name: "case insensitive", cname: "U123.WL.SendGrid.NET", want: vendorSendGrid},
		{name: vendorEngageLab, cname: "track01.engagelab.email", want: vendorEngageLab},
		{name: "mailchimp", cname: "x.list-manage.com", want: "mailchimp"},
		{name: "unrelated", cname: "cdn.cloudflare.net", want: ""},
		{name: "empty", cname: "", want: ""},
		{name: "suffix must be a label boundary", cname: "notsendgrid.net", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := corpus.MatchCNAME(tt.cname)
			assert.Equal(t, tt.want != "", ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestCorpusDedupesByShape proves selection actually narrows: many URLs that
// test one code path become one or two requests.
func TestCorpusDedupesByShape(t *testing.T) {
	t.Parallel()

	c := corpus.New()

	urls := []string{}
	for _, id := range []string{"1", "2", "3", "4", "5", "6", "7", "8"} {
		urls = append(urls, "https://a.lab/article/"+id+"?next=/home")
	}

	kept := c.AddAll(urls)
	assert.Equal(t, 2, kept, "eight identical shapes collapse to two")
	assert.Equal(t, 2, c.Len())
}

// TestCorpusKeepsEveryVendorWrapper is the deliberate exception: a wrapper is
// a product, and every instance carries a different envelope.
func TestCorpusKeepsEveryVendorWrapper(t *testing.T) {
	t.Parallel()

	c := corpus.New()

	urls := []string{}
	for _, blob := range []string{
		"eJxLyU9OLcpMzFEoLsnMS1cAAFnnBJk",
		"eJyrVkrLz1eyUsrJT84uLikCAB0TBHk",
		"eJxLyU9OLcpMzFEoLsnMS1cAAFnnBJl",
		"eJyrVkrLz1eyUsrJT84uLikCAB0TBHl",
	} {
		urls = append(urls, "https://trace.a.lab/track/click2/"+blob)
	}

	kept := c.AddAll(urls)
	assert.Equal(t, 4, kept, "every wrapper instance is kept")
}

// TestCorpusPriorityOrder is the order a hunter would work in.
func TestCorpusPriorityOrder(t *testing.T) {
	t.Parallel()

	c := corpus.New()
	c.AddAll([]string{
		"https://a.lab/t/eJxLyU9OLcpMzFEoLsnMS1cAAFnnBJk",
		"https://a.lab/go?next=/home",
		"https://a.lab/p?image=https://cdn.a.lab/x",
		"https://mail.a.lab/ls/click?upn=eyJ1cmwiOiJodHRwczovL2EuYi8ifQ",
	})

	entries := c.Entries()
	require.Len(t, entries, 4)
	assert.True(t, entries[0].Has(corpus.KindVendorSig), "vendor wrapper first")
	assert.True(t, entries[1].Has(corpus.KindParamValue), "then a url-shaped value")
	assert.True(t, entries[2].Has(corpus.KindParamName), "then a redirect-shaped name")
	assert.True(t, entries[3].Has(corpus.KindPath), "then a merely opaque path")
}

func TestCorpusDropsDuplicatesAndJunk(t *testing.T) {
	t.Parallel()

	c := corpus.New()
	kept := c.AddAll([]string{
		urlGoWithURL,
		urlGoWithURL,
		"HTTPS://A.LAB/go?url=x",
		"https://a.lab/style.css?url=x",
		"not a url",
		"",
	})

	assert.Equal(t, 1, kept)
	assert.Equal(t, []string{urlGoWithURL}, c.URLs())
}
