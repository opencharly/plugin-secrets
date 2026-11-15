package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

// TestStripMigratedPlaintextKeepsTheShadowIndex is the regression test for the persistence half of
// `charly secrets migrate-secrets`.
//
// The migration writes each value through KeyringStore.Set, which appends the credential to the
// keyring SHADOW INDEX and saves config.yml. The save that strips the plaintext therefore has to
// start from a FRESH load: the RuntimeConfig captured before the loop predates every one of those
// index writes, so writing it back rewrote `keyring_keys` to its stale value and left the migrated
// credentials in the keyring with nothing pointing at them. `list` and `export` read the index, so
// the store then reported "no entries" over a store that held them
// (measured on opencharly/plugin-secrets#9).
func TestStripMigratedPlaintextKeepsTheShadowIndex(t *testing.T) {
	dir := t.TempDir()
	RuntimeConfigPath = func() (string, error) { return filepath.Join(dir, "config.yml"), nil }
	t.Cleanup(func() { RuntimeConfigPath = defaultRuntimeConfigPath })

	// The on-disk state AFTER the migration loop: the value reached the keyring, the index records
	// it, and the plaintext the loop has not stripped yet is still in vnc_passwords. PRESET_ENTRY
	// is an index entry that existed before this run; NEW_MIGRATED's entry was added by it.
	const onDisk = `keyring_keys:
    - charly/secret/NEW_MIGRATED
    - charly/secret/PRESET_ENTRY
vnc_passwords:
    charly/secret/NEW_MIGRATED: NEW-VALUE
    charly/secret/KEPT_BY_FAILED_WRITE: STILL-HERE
`
	path := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(path, []byte(onDisk), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	if err := stripMigratedPlaintext([]credID{{service: "charly/secret", key: "NEW_MIGRATED"}}); err != nil {
		t.Fatalf("stripMigratedPlaintext: %v", err)
	}

	got, err := LoadRuntimeConfig()
	if err != nil {
		t.Fatalf("re-reading config: %v", err)
	}

	// The index must still name the credential the migration just wrote — that is the half the
	// stale save destroyed.
	ids := map[string]bool{}
	for _, entry := range got.KeyringKeys {
		ids[entry] = true
	}
	for _, want := range []string{"charly/secret/NEW_MIGRATED", "charly/secret/PRESET_ENTRY"} {
		if !ids[want] {
			t.Errorf("index entry %q was lost; index is %v", want, got.KeyringKeys)
		}
	}

	// Only the migrated plaintext may leave the map: an entry whose keyring write FAILED keeps its
	// value, because nothing else holds it.
	if val := lookupConfigCredential(got, "charly/secret", "NEW_MIGRATED"); val != "" {
		t.Errorf("migrated plaintext survived: %q", val)
	}
	if val := lookupConfigCredential(got, "charly/secret", "KEPT_BY_FAILED_WRITE"); val != "STILL-HERE" {
		t.Errorf("non-migrated plaintext = %q, want STILL-HERE (a failed write must keep its value)", val)
	}
}
