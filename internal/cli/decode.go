package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/nedlir/detour/internal/client"
	"github.com/nedlir/detour/internal/config"
	"github.com/nedlir/detour/internal/decode"
	"github.com/spf13/cobra"
)

// maxReplayBody is how much of a replayed response body is drained so the
// connection can be reused. Nothing from it is parsed.
const maxReplayBody = 1 << 16

func newDecodeCmd() *cobra.Command {
	var matrix bool

	cmd := &cobra.Command{
		Use:   "decode url",
		Short: "Open opaque navigation state hidden in a URL",
		Long: "decode finds high-entropy path segments and parameter values, unwraps them through a reversible " +
			"decoder chain, and reports every navigation destination inside, at any depth.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDecode(cmd, args[0], matrix)
		},
	}

	cmd.Flags().BoolVar(&matrix, "matrix", false,
		"replay the envelope with each field flipped to record what the server validates")

	return cmd
}

// blobReport is one decoded envelope as detour decode prints it.
type blobReport struct {
	Site    decode.Site       `json:"site"`
	Token   string            `json:"token"`
	Layers  []string          `json:"layers"`
	Value   any               `json:"value"`
	Fields  []decode.URLField `json:"url_fields"`
	Mutated string            `json:"mutated,omitempty"`
	Matrix  *decode.Matrix    `json:"field_matrix,omitempty"`
}

type decodeReport struct {
	Source string       `json:"source"`
	Blobs  []blobReport `json:"blobs"`
}

func runDecode(cmd *cobra.Command, source string, matrix bool) error {
	cfg, ok := config.FromContext(cmd.Context())
	if !ok {
		return errors.New("config not loaded")
	}

	blobs, err := decode.Find(source)
	if err != nil {
		return err
	}

	replayer, err := decodeReplayer(cfg, matrix)
	if err != nil {
		return err
	}

	report := decodeReport{Source: source, Blobs: make([]blobReport, 0, len(blobs))}

	for _, b := range blobs {
		item, err := describeBlob(cmd.Context(), b, source, cfg.Destination(), replayer)
		if err != nil {
			return err
		}

		report.Blobs = append(report.Blobs, item)
	}

	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")

	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("writing decode report: %w", err)
	}

	_, err = fmt.Fprintf(cmd.ErrOrStderr(), "%d opaque blobs\n", len(report.Blobs))

	return err
}

func decodeReplayer(cfg config.Config, matrix bool) (decode.Replayer, error) {
	if !matrix {
		return nil, nil
	}

	guard, err := guardFromConfig(cfg)
	if err != nil {
		return nil, err
	}

	c, err := client.New(cfg, guard)
	if err != nil {
		return nil, err
	}

	return &httpReplayer{client: c}, nil
}

func describeBlob(
	ctx context.Context,
	b decode.Blob,
	source, canary string,
	replayer decode.Replayer,
) (blobReport, error) {
	item := blobReport{
		Site:   b.Site,
		Token:  b.Token,
		Layers: layerNames(b.Chain),
		Value:  b.Chain.Value,
		Fields: b.Fields,
	}

	if len(b.Fields) > 0 {
		mutated, err := b.Replace(source, b.Fields[0], "https://"+canary+"/")
		if err != nil {
			return blobReport{}, err
		}

		item.Mutated = mutated
	}

	if replayer == nil {
		return item, nil
	}

	m, err := decode.BuildMatrix(ctx, b, source, replayer)
	if err != nil {
		return blobReport{}, err
	}

	item.Matrix = &m

	return item, nil
}

func layerNames(chain *decode.Chain) []string {
	out := make([]string, 0, len(chain.Layers))
	for _, l := range chain.Layers {
		out = append(out, l.Name())
	}

	return out
}

// httpReplayer replays an envelope through the shared scoped client. It never
// follows a redirect; the Location header is the whole answer.
type httpReplayer struct {
	client *client.Client
}

func (h *httpReplayer) Replay(ctx context.Context, rawURL string) (decode.Outcome, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return decode.Outcome{}, fmt.Errorf("building replay request: %w", err)
	}

	resp, err := h.client.Do(ctx, req)
	if err != nil {
		return decode.Outcome{}, fmt.Errorf("replaying envelope: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxReplayBody))

	return decode.Outcome{
		Status:   resp.StatusCode,
		Location: resp.Header.Get("Location"),
	}, nil
}
