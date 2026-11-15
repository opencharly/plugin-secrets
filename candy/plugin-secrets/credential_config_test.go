package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPlaintextCredentialEntriesTwoSegmentService pins the identity of a credential stored under
// the documented shared namespace `charly/<ns>/<name>` — the shape the `secrets` skill recommends
// (`charly secrets set charly/api-key openrouter …`) and the shape a candy's
// `secret_accept: [{name: OPENROUTER_API_KEY, key: charly/api-key/openrouter}]` writes.
//
// The key is the LAST segment, so a service may contain slashes. This is the case the parser used
// to get wrong: it special-cased `charly/secret/` and `charly/enc/` and cut every OTHER service at
// the FIRST slash, yielding (service="charly", key="api-key/openrouter") for a value the writer
// had stored under (service="charly/api-key", key="openrouter"). A Secret Service item's identity
// IS its attribute pair, so `migrate-secrets`/`import` moved such a credential to a coordinate
// nothing could read it back from (opencharly/plugin-secrets#9).
func TestPlaintextCredentialEntriesTwoSegmentService(t *testing.T) {
	cfg := &RuntimeConfig{VncPasswords: map[string]string{
		"charly/api-key/openrouter": "sk-or-test",
		"charly/secret/AUDIT_TOKEN": "tok",
		"my-image":                  "vncpass",
	}}

	want := map[string]struct{ service, key string }{
		"sk-or-test": {"charly/api-key", "openrouter"},
		"tok":        {"charly/secret", "AUDIT_TOKEN"},
		"vncpass":    {CredServiceVNC, "my-image"},
	}
	entries := PlaintextCredentialEntries(cfg)
	if len(entries) != len(want) {
		t.Fatalf("PlaintextCredentialEntries len = %d, want %d", len(entries), len(want))
	}
	for _, e := range entries {
		w, ok := want[e.Value]
		if !ok {
			t.Errorf("unexpected entry %q/%q (value %q)", e.Service, e.Key, e.Value)
			continue
		}
		if e.Service != w.service || e.Key != w.key {
			t.Errorf("%q parsed as service=%q key=%q, want service=%q key=%q",
				e.Value, e.Service, e.Key, w.service, w.key)
		}
	}
}

// TestCollectCredentialNamesUsesTheOneSplit proves that what `charly secrets list`/`export` PRINT
// is the identity `charly secrets get` looks up: both sides go through the one composite-key split,
// so a two-segment service cannot be named one way by the index and another by the store.
//
// The index is the config file's `keyring_keys` — written by KeyringStore.Set as "service/key",
// i.e. with the same last-segment convention the deploy path builds these strings with.
func TestCollectCredentialNamesUsesTheOneSplit(t *testing.T) {
	dir := t.TempDir()
	RuntimeConfigPath = func() (string, error) { return filepath.Join(dir, "config.yml"), nil }
	t.Cleanup(func() { RuntimeConfigPath = defaultRuntimeConfigPath })

	const indexYAML = `keyring_keys:
    - charly/api-key/openrouter
    - charly/secret/AUDIT_TOKEN
`
	if err := os.WriteFile(filepath.Join(dir, "config.yml"), []byte(indexYAML), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	names, err := collectCredentialNames()
	if err != nil {
		t.Fatalf("collectCredentialNames: %v", err)
	}
	want := []struct{ service, key string }{
		{"charly/api-key", "openrouter"},
		{"charly/secret", "AUDIT_TOKEN"},
	}
	for _, w := range want {
		found := false
		for _, n := range names {
			if n.Service == w.service && n.Key == w.key {
				found = true
			}
		}
		if !found {
			t.Errorf("collectCredentialNames did not yield %s/%s (got %+v)", w.service, w.key, names)
		}
	}
	// A mis-split would surface as service="charly", key="api-key/openrouter"; nothing may.
	for _, n := range names {
		if n.Service == "charly" {
			t.Errorf("collectCredentialNames split a two-segment service at the first slash: %+v", n)
		}
	}
}

// TestParseCompositeKeyLastSegment is the direct contract of the one split: the key is always the
// last segment, whatever the service looks like — that is what the deploy path, the index reader
// and the doctor's consistency probe all assume.
func TestParseCompositeKeyLastSegment(t *testing.T) {
	cases := []struct{ composite, service, key string }{
		{"charly/secret/TOK", "charly/secret", "TOK"},
		{"charly/enc/myapp", "charly/enc", "myapp"},
		{"charly/api-key/openrouter", "charly/api-key", "openrouter"},
		{"charly/vnc/my-image", "charly/vnc", "my-image"},
		{"my-image", CredServiceVNC, "my-image"},
	}
	for _, c := range cases {
		service, key := parseCompositeKey(c.composite)
		if service != c.service || key != c.key {
			t.Errorf("parseCompositeKey(%q) = (%q, %q), want (%q, %q)",
				c.composite, service, key, c.service, c.key)
		}
	}
}
