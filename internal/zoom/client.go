// Package zoom posts messages into a Zoom Team Chat channel through an
// incoming webhook.
//
// The direction is one way, and the name is written from Zoom's point of view:
// an "incoming webhook" is incoming to Zoom, so this package sends and never
// receives. Reading questions out of a channel needs a Zoom Marketplace app
// with a Team Chat bot, which is a different credential, a different endpoint,
// and an inbound path from Zoom's cloud to a host we run.
//
// The wire contract is documented at
// https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0067640
// and is easy to get wrong in ways that produce a bare 400:
//
//   - The timestamp is a QUERY PARAMETER in MILLISECONDS, not a header. A
//     timestamp sent as a header returns "400 Bad Request: Missed timestamp".
//   - The signature covers "{format}&{timestamp}&{message}", not the body
//     alone, and is base64 rather than hex.
//   - Authorization carries the bare signature, with no scheme prefix.
//   - For format=message the body is the raw message text. The documentation
//     writes it as "This is a test message." and the quotes are illustrative:
//     send them and Zoom prints them, because it never parses the body as
//     JSON. Confirmed by a probe message that arrived in-channel still
//     wearing its quotes.
package zoom

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// maxMessageBytes is a conservative bound on one Zoom chat message. Zoom
// rejects an over-long message outright rather than truncating it, which for a
// digest means the whole post is lost rather than its tail, so long content is
// split here instead.
const maxMessageBytes = 3500

// formatMessage is the simplest of Zoom's body formats (message, fields, list,
// full, upload, img). It carries plain text, which is all a digest needs.
const formatMessage = "message"

// Variant captures the two things Zoom's documentation states but does not
// pin down: what "input message" means in the signature string, and whether
// base64UrlEncode means the URL-safe alphabet or the standard one.
//
// Both were settled against the live endpoint on 2026-08-30: "input message"
// is the exact body POSTed, quotes included, and base64UrlEncode means the
// standard alphabet. The other three constructions returned 401 "Invalid
// signature". Probe remains because that measurement is one account on one
// day, and a 401 is otherwise indistinguishable from a bad secret.
type Variant struct {
	Name string
	// HashRawBody hashed the exact bytes POSTed back when those were a JSON
	// string literal. Now that the body is the raw text, this and its opposite
	// produce identical bytes, and Probe groups them accordingly. It is kept
	// because Zoom's other body formats are objects, where the distinction
	// returns.
	HashRawBody bool
	URLSafe     bool
}

// Variants are ordered by how likely each is to be the real contract. Signing
// the bytes actually sent is the ordinary convention, so it leads.
var Variants = []Variant{
	{Name: "raw-body/standard", HashRawBody: true, URLSafe: false},
	{Name: "raw-body/urlsafe", HashRawBody: true, URLSafe: true},
	{Name: "plain-text/standard", HashRawBody: false, URLSafe: false},
	{Name: "plain-text/urlsafe", HashRawBody: false, URLSafe: true},
}

// DefaultVariant is the construction Zoom accepted on 2026-08-30. Override it
// with SROIAAA_ZOOM_SIGNATURE_VARIANT rather than editing here, and rerun
// -probe before changing it: the other three are not near-misses, they are
// rejected outright.
var DefaultVariant = Variants[0]

type Config struct {
	// URL is the endpoint /inc connect returned. It encodes which channel the
	// message lands in, so it is as sensitive as the credential beside it.
	URL string
	// Token authenticates a connection made with "/inc connect".
	Token string
	// Secret authenticates a connection made with "/inc connect -s", by signing
	// each payload rather than sending a shared static string. Prefer it.
	Secret string
	// Variant selects the signature construction. Zero value means
	// DefaultVariant.
	Variant *Variant

	HTTPClient *http.Client
}

type Client struct {
	url     string
	token   string
	secret  string
	variant Variant
	http    *http.Client
	now     func() time.Time
}

func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, fmt.Errorf("zoom: webhook URL is empty")
	}
	if !strings.HasPrefix(cfg.URL, "https://") {
		// The credential travels on every call. Over plain HTTP it travels in
		// clear text to whoever is between here and Zoom.
		return nil, fmt.Errorf("zoom: webhook URL must be https")
	}
	if _, err := url.Parse(cfg.URL); err != nil {
		return nil, fmt.Errorf("zoom: webhook URL is not a URL: %w", err)
	}
	if cfg.Token == "" && cfg.Secret == "" {
		return nil, fmt.Errorf("zoom: set either a token or a signing secret")
	}
	variant := DefaultVariant
	if cfg.Variant != nil {
		variant = *cfg.Variant
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		url:     cfg.URL,
		token:   cfg.Token,
		secret:  cfg.Secret,
		variant: variant,
		http:    client,
		now:     time.Now,
	}, nil
}

// Post sends text to the channel, splitting it when it exceeds what Zoom will
// accept in one message. The first failure stops the rest: a partial digest
// that says it is partial beats one that ends mid-sentence.
func (c *Client) Post(ctx context.Context, text string) error {
	chunks := split(text, maxMessageBytes)
	if len(chunks) == 0 {
		return fmt.Errorf("zoom: nothing to post")
	}
	for i, chunk := range chunks {
		if len(chunks) > 1 {
			chunk = fmt.Sprintf("(%d/%d)\n%s", i+1, len(chunks), chunk)
		}
		if err := c.postOne(ctx, chunk); err != nil {
			if i == 0 {
				return err
			}
			return fmt.Errorf("zoom: sent %d of %d parts: %w", i, len(chunks), err)
		}
	}
	return nil
}

func (c *Client) postOne(ctx context.Context, text string) error {
	// Zoom expects milliseconds here and rejects a signature whose timestamp is
	// more than half an hour old.
	return c.postAt(ctx, text, strconv.FormatInt(c.now().UnixMilli(), 10))
}

func (c *Client) postAt(ctx context.Context, text, timestamp string) error {
	body := []byte(text)

	endpoint, err := url.Parse(c.url)
	if err != nil {
		return fmt.Errorf("zoom: parse URL: %w", err)
	}
	query := endpoint.Query()
	query.Set("format", formatMessage)
	if c.secret != "" {
		query.Set("timestamp", timestamp)
	}
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("zoom: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.secret != "" {
		req.Header.Set("Authorization", Sign(c.secret, formatMessage, timestamp, text, body, c.variant))
	} else {
		req.Header.Set("Authorization", c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("zoom: post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Zoom names the offending field in the body, and that name is the whole
		// diagnostic: "Missed timestamp" is what a header-borne timestamp gets.
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("zoom: %s: %s", resp.Status, strings.TrimSpace(string(detail)))
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return nil
}

// Sign builds the Authorization value:
//
//	base64(HMAC-SHA256("{format}&{timestamp}&{message}", secret))
//
// with no scheme prefix. It takes both the plain text and the encoded body so
// that a Variant can select which one Zoom means by "input message".
func Sign(secret, format, timestamp, text string, body []byte, v Variant) string {
	message := text
	if v.HashRawBody {
		message = string(body)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	io.WriteString(mac, format+"&"+timestamp+"&"+message)
	sum := mac.Sum(nil)
	if v.URLSafe {
		return base64.URLEncoding.EncodeToString(sum)
	}
	return base64.StdEncoding.EncodeToString(sum)
}

// ProbeResult reports one distinct request the probe sent. Variants that
// produce byte-identical signatures are grouped, because sending the same
// request twice would waste a message and prove nothing.
type ProbeResult struct {
	Variants []string
	Accepted bool
	Err      error
}

// Probe settles the two things Zoom's documentation states without pinning
// down: what "input message" covers in the signature string, and which base64
// alphabet base64UrlEncode means.
//
// The text and timestamp are held fixed across variants so that the only thing
// varying is the signature construction. Standard and URL-safe base64 differ
// only when the digest contains a byte encoding to '+' or '/', which is why
// variants are grouped by the signature they actually produce rather than
// assumed distinct: without that, two constructions can both look accepted
// when only one request was ever really tried.
func (c *Client) Probe(ctx context.Context) ([]ProbeResult, error) {
	if c.secret == "" {
		return nil, fmt.Errorf("zoom: probe needs a signing secret")
	}
	text := "cass signature probe"
	timestamp := strconv.FormatInt(c.now().UnixMilli(), 10)
	body := []byte(text)

	var results []ProbeResult
	index := map[string]int{}
	for _, variant := range Variants {
		signature := Sign(c.secret, formatMessage, timestamp, text, body, variant)
		if at, seen := index[signature]; seen {
			results[at].Variants = append(results[at].Variants, variant.Name)
			continue
		}
		index[signature] = len(results)
		results = append(results, ProbeResult{Variants: []string{variant.Name}})
	}

	for i := range results {
		attempt := *c
		if v, err := VariantByName(results[i].Variants[0]); err == nil && v != nil {
			attempt.variant = *v
		}
		if err := attempt.postAt(ctx, text, timestamp); err != nil {
			results[i].Err = err
			continue
		}
		results[i].Accepted = true
	}
	return results, nil
}

// split breaks text into chunks no larger than limit bytes, preferring a line
// boundary. A line longer than the limit on its own is cut, because the
// alternative is refusing to send it at all.
func split(text string, limit int) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	if len(text) <= limit {
		return []string{text}
	}
	var chunks []string
	var current strings.Builder
	flush := func() {
		if current.Len() > 0 {
			chunks = append(chunks, strings.TrimRight(current.String(), "\n"))
			current.Reset()
		}
	}
	for _, line := range strings.Split(text, "\n") {
		for len(line) > limit {
			flush()
			chunks = append(chunks, line[:limit])
			line = line[limit:]
		}
		if current.Len()+len(line)+1 > limit {
			flush()
		}
		current.WriteString(line)
		current.WriteString("\n")
	}
	flush()
	return chunks
}

// VariantByName resolves an override, so a confirmed variant can be selected
// without a rebuild.
func VariantByName(name string) (*Variant, error) {
	if name == "" {
		return nil, nil
	}
	for i := range Variants {
		if Variants[i].Name == name {
			return &Variants[i], nil
		}
	}
	names := make([]string, 0, len(Variants))
	for _, v := range Variants {
		names = append(names, v.Name)
	}
	return nil, fmt.Errorf("zoom: unknown signature variant %q (have %s)", name, strings.Join(names, ", "))
}

// Describe renders the request Post would send, without sending it. A dry run
// that shows the real query string, headers, and body is how a wire-format
// problem gets diagnosed without spending a message in a channel.
func (c *Client) Describe(text string) (string, error) {
	timestamp := strconv.FormatInt(c.now().UnixMilli(), 10)
	body := []byte(text)
	endpoint, err := url.Parse(c.url)
	if err != nil {
		return "", err
	}
	query := endpoint.Query()
	query.Set("format", formatMessage)
	authorization := c.token
	if c.secret != "" {
		query.Set("timestamp", timestamp)
		authorization = Sign(c.secret, formatMessage, timestamp, text, body, c.variant)
	}
	endpoint.RawQuery = query.Encode()

	var out strings.Builder
	fmt.Fprintf(&out, "POST %s\n", redactURL(endpoint))
	fmt.Fprintf(&out, "Content-Type: application/json\n")
	fmt.Fprintf(&out, "Authorization: %s\n", redactSecret(authorization, c.secret == ""))
	if c.secret != "" {
		fmt.Fprintf(&out, "\nsigned as: %s\n", c.variant.Name)
		signed := text
		if c.variant.HashRawBody {
			signed = string(body)
		}
		fmt.Fprintf(&out, "signature covers: %s&%s&%s\n", formatMessage, timestamp, signed)
	}
	fmt.Fprintf(&out, "\n%s\n", body)
	return out.String(), nil
}

// redactURL renders a webhook endpoint for human eyes without handing over the
// endpoint itself.
//
// This file already says a webhook URL must never reach "a command line, a
// shell history, or a cron table", and then -dry-run printed it to a terminal,
// where it goes into scrollback, a pasted bug report, or a screen share. The
// URL is not merely a location: /inc connect mints it per channel, so it names
// which channel a message lands in and is as sensitive as the credential it
// travels with.
//
// What survives is what a person debugging actually needs: the scheme, the
// host, the shape of the path, and which parameters are present. What goes is
// every opaque identifier.
//
// Opacity, not length, decides. The first attempt redacted any segment past 12
// characters and swallowed "incomingwebhook" along with the id after it, which
// removes the one part of the path that says what the request is. A minted
// identifier mixes case or digits; a route word does not.
func redactURL(endpoint *url.URL) string {
	shown := *endpoint

	segments := strings.Split(shown.Path, "/")
	for i, segment := range segments {
		if looksMinted(segment) {
			segments[i] = fmt.Sprintf("REDACTED-%d", len(segment))
		}
	}
	shown.Path = strings.Join(segments, "/")

	// format and timestamp are computed here and carry nothing private; every
	// other parameter is assumed to. An allowlist rather than a blocklist, so
	// a parameter added later is redacted by default rather than exposed by
	// having been forgotten.
	// The marker is URL-safe on purpose. "<redacted:44>" comes back out of
	// URL.String() as "%3Credacted:44%3E", which is the sort of output a
	// person skims past instead of reading.
	query := shown.Query()
	for key, values := range query {
		if key == "format" || key == "timestamp" {
			continue
		}
		for i := range values {
			values[i] = fmt.Sprintf("REDACTED-%d", len(values[i]))
		}
		query[key] = values
	}
	shown.RawQuery = query.Encode()

	if shown.User != nil {
		shown.User = url.User("REDACTED")
	}
	return shown.String()
}

// redactSecret describes a credential without printing it.
//
// With a secret configured this is a per-message signature, which is spent as
// soon as its timestamp ages out; with only a token it is the shared static
// credential itself, and printing that is handing it over. Neither is shown.
// The length and the kind are enough to tell "the wrong variant signed it"
// from "the token is missing", which is what -dry-run is for.
func redactSecret(value string, isStaticToken bool) string {
	kind := "signature"
	if isStaticToken {
		kind = "static token"
	}
	if value == "" {
		return fmt.Sprintf("<no %s>", kind)
	}
	return fmt.Sprintf("<redacted: %d-character %s>", len(value), kind)
}

// looksMinted reports whether a path segment is an identifier rather than a
// word someone chose. Minted ids carry digits or mixed case; route words like
// "chat", "webhooks" and "incomingwebhook" carry neither. Anything past 24
// characters is treated as minted regardless, because no route word is that
// long and a lowercase-only id would otherwise slip through.
func looksMinted(segment string) bool {
	if len(segment) <= 12 {
		return false
	}
	if len(segment) > 24 {
		return true
	}
	for _, r := range segment {
		if (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') {
			return true
		}
	}
	return false
}
