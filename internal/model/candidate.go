package model

// Representation is how a navigation destination is carried.
type Representation int

const (
	// RepresentationUnknown is the zero value; a candidate must not stay here.
	RepresentationUnknown Representation = iota
	// RepresentationQueryParameter is a ?key= destination.
	RepresentationQueryParameter
	// RepresentationPathSegment is a path component, including opaque blobs.
	RepresentationPathSegment
	// RepresentationFragment is a #fragment destination.
	RepresentationFragment
	// RepresentationHeader is a request or response header value.
	RepresentationHeader
	// RepresentationCookie is a cookie value.
	RepresentationCookie
	// RepresentationJSONBody is a JSON request-body field.
	RepresentationJSONBody
	// RepresentationFormBody is a form-encoded body field.
	RepresentationFormBody
	// RepresentationOpaqueBlob is structured state reached through DecoderChain.
	RepresentationOpaqueBlob
	// RepresentationJSExpression is a client-side expression feeding a sink.
	RepresentationJSExpression
)

var representationNames = map[Representation]string{
	RepresentationUnknown:        "unknown",
	RepresentationQueryParameter: "query_parameter",
	RepresentationPathSegment:    "path_segment",
	RepresentationFragment:       "fragment",
	RepresentationHeader:         "header",
	RepresentationCookie:         "cookie",
	RepresentationJSONBody:       "json_body",
	RepresentationFormBody:       "form_body",
	RepresentationOpaqueBlob:     "opaque_blob",
	RepresentationJSExpression:   "js_expression",
}

// String returns the stable wire name for r.
func (r Representation) String() string {
	if name, ok := representationNames[r]; ok {
		return name
	}

	return representationNames[RepresentationUnknown]
}

// ParseRepresentation maps a wire name to a Representation.
func ParseRepresentation(s string) (Representation, bool) {
	for rep, name := range representationNames {
		if name == s {
			return rep, true
		}
	}

	return RepresentationUnknown, false
}

// NavigationCandidate is the engine's unit of work. Query parameters, path
// blobs, headers, cookies, and JS expressions all flow through this type.
type NavigationCandidate struct {
	SourceURL      string         `json:"source_url"`
	Representation Representation `json:"representation"`
	ParamName      string         `json:"param_name,omitempty"`
	DecoderChain   []Decoder      `json:"decoder_chain,omitempty"`
	URLFields      []FieldPath    `json:"url_fields,omitempty"`
	Validator      *Validator     `json:"validator,omitempty"`
	Capabilities   CapabilitySet  `json:"capabilities"`
}

// NewNavigationCandidate returns a candidate with slices initialized.
func NewNavigationCandidate(sourceURL string, rep Representation) NavigationCandidate {
	return NavigationCandidate{
		SourceURL:      sourceURL,
		Representation: rep,
		DecoderChain:   []Decoder{},
		URLFields:      []FieldPath{},
		Capabilities:   NewCapabilitySet(),
	}
}

// Clone returns a deep copy of the candidate.
func (c NavigationCandidate) Clone() NavigationCandidate {
	out := c
	if c.DecoderChain != nil {
		out.DecoderChain = append([]Decoder{}, c.DecoderChain...)
	}

	if c.URLFields != nil {
		out.URLFields = append([]FieldPath{}, c.URLFields...)
	}

	out.Validator = c.Validator.Clone()
	out.Capabilities = c.Capabilities.Clone()

	return out
}
