package secrets

import (
	"errors"
	"testing"

	"github.com/alecthomas/kong"
	dbus "github.com/godbus/dbus/v5"
)

// TestStaleIndexEntries drives `charly secrets prune`'s classification: an index entry whose
// (service, username) pair is in NO reachable collection is drift; one that resolves anywhere is
// kept, even when it lives in a collection other than the default.
//
// The classification is what the drift message in KeyringStore.Get has always promised
// ("Run `charly secrets prune` to reconcile") and what the verb now delivers
// (opencharly/plugin-secrets#9).
func TestStaleIndexEntries(t *testing.T) {
	const login = dbus.ObjectPath("/collections/login")
	const keepass = dbus.ObjectPath("/collections/keepass")

	f := newFakeSSOps()
	f.aliasMap["default"] = login
	f.collectionList = []dbus.ObjectPath{login, keepass}
	f.labels[login] = "Login"
	f.labels[keepass] = "opencharly"
	f.addItemWithAttrs(login,
		map[string]string{"service": "charly/secret", "username": "PRESENT"},
		"/items/present", []byte("v"), "")
	f.addItemWithAttrs(keepass,
		map[string]string{"service": "charly/api-key", "username": "openrouter"},
		"/items/elsewhere", []byte("v"), "")

	keys := []string{
		"charly/secret/PRESENT",     // in the default collection
		"charly/api-key/openrouter", // in a NON-default collection (two-segment service)
		"charly/secret/GONE",        // nowhere: stale
	}
	stale, err := staleIndexEntries(f, keys, "")
	if err != nil {
		t.Fatalf("staleIndexEntries: %v", err)
	}
	if len(stale) != 1 || stale[0] != "charly/secret/GONE" {
		t.Errorf("stale = %v, want exactly [charly/secret/GONE]", stale)
	}
}

// TestStaleIndexEntriesNeverTreatsBrokenKeyringAsDrift is the safety property: prune drops index
// entries, which are the only record that a credential exists. A keyring that could not be READ
// (every collection broken, or locked behind an interactive prompt) must therefore abort the
// command with an error rather than be classified as "the credentials are gone" — otherwise a
// transient condition would empty the whole index.
func TestStaleIndexEntriesNeverTreatsBrokenKeyringAsDrift(t *testing.T) {
	const only = dbus.ObjectPath("/collections/only")

	f := newFakeSSOps()
	f.collectionList = []dbus.ObjectPath{only}
	f.labels[only] = "Login"
	f.searchErrs[only] = errors.New("dbus: connection closed")

	if _, err := staleIndexEntries(f, []string{"charly/secret/TOK"}, ""); err == nil {
		t.Fatal("staleIndexEntries accepted a broken keyring as drift; every index entry would be dropped")
	}

	g := newFakeSSOps()
	const locked = dbus.ObjectPath("/collections/locked")
	g.collectionList = []dbus.ObjectPath{locked}
	g.labels[locked] = "Locked"
	g.unlockErrs[locked] = ErrSSInteractiveUnlockRequired
	if _, err := staleIndexEntries(g, []string{"charly/secret/TOK"}, ""); err == nil {
		t.Fatal("staleIndexEntries accepted a locked keyring as drift; every index entry would be dropped")
	}
}

// TestSecretsCLI_PruneIsRegistered proves the verb actually reaches the CLI: `charly secrets prune`
// was promised in two operator-facing messages while being absent from the command group, so
// "the command parses with --dry-run" is the assertion that closes that gap.
func TestSecretsCLI_PruneIsRegistered(t *testing.T) {
	var grp SecretsCmdGroup
	parser, err := kong.New(&grp)
	if err != nil {
		t.Fatalf("building parser: %v", err)
	}
	if _, err := parser.Parse([]string{"prune", "--dry-run"}); err != nil {
		t.Fatalf("parsing `secrets prune --dry-run`: %v", err)
	}
	if !grp.Prune.DryRun {
		t.Error("--dry-run did not reach PruneSecretsCmd")
	}
}
