package secrets

import (
	"errors"
	"testing"

	dbus "github.com/godbus/dbus/v5"
)

// The tests here pin the ONE Secret Service write/delete mechanism. Both used to go through
// zalando/go-keyring, whose Linux provider resolves ONE collection — /collection/login when it
// exists, else the `default` alias — and ignores keyring_collection_label, while the READ path
// iterates default → keyring_collection_label → every healthy collection. Two consequences, both
// from that mismatch (opencharly/plugin-secrets#9): `keyring_collection_label` was honoured on
// reads only, and `charly secrets delete` could not find — and therefore could not delete — a
// credential that lived in any other collection, while reporting success and dropping its index
// entry.

// TestKeyringSetLandsInTheLabelledCollection: with no `default` alias — the shape a KeePassXC-only
// host has — a write must land in the collection the operator pinned, not in `login`.
func TestKeyringSetLandsInTheLabelledCollection(t *testing.T) {
	const login = dbus.ObjectPath("/collections/login")
	const keepass = dbus.ObjectPath("/collections/keepass")

	f := newFakeSSOps()
	f.collectionList = []dbus.ObjectPath{login, keepass}
	f.labels[login] = "Login"
	f.labels[keepass] = "opencharly"

	if err := keyringSetViaSSClient(f, "charly/api-key", "openrouter", "sk-or-test", "opencharly"); err != nil {
		t.Fatalf("keyringSetViaSSClient: %v", err)
	}
	if got := len(f.items[keepass]); got != 1 {
		t.Errorf("labelled collection holds %d item(s), want 1", got)
	}
	if got := len(f.items[login]); got != 0 {
		t.Errorf("write landed in the login collection (%d item(s)); keyring_collection_label was ignored", got)
	}

	// …and the read path finds it back at the same coordinate, which is the point of co-locating.
	if _, label, err := findItemByAttrsAcrossCollections(f,
		map[string]string{"service": "charly/api-key", "username": "openrouter"}, "opencharly"); err != nil {
		t.Fatalf("read back: %v", err)
	} else if label != "opencharly" {
		t.Errorf("read served by collection %q, want opencharly", label)
	}
}

// TestKeyringSetPrefersTheDefaultCollection: when a `default` alias exists the write goes there, so
// writes co-locate with reads (resolveTargetCollection and findItemByAttrsAcrossCollections share
// the same priority order).
func TestKeyringSetPrefersTheDefaultCollection(t *testing.T) {
	const def = dbus.ObjectPath("/collections/default")
	const keepass = dbus.ObjectPath("/collections/keepass")

	f := newFakeSSOps()
	f.aliasMap["default"] = def
	f.collectionList = []dbus.ObjectPath{def, keepass}
	f.labels[def] = "Login"
	f.labels[keepass] = "opencharly"

	if err := keyringSetViaSSClient(f, "charly/secret", "TOK", "v", "opencharly"); err != nil {
		t.Fatalf("keyringSetViaSSClient: %v", err)
	}
	if got := len(f.items[def]); got != 1 {
		t.Errorf("default collection holds %d item(s), want 1", got)
	}
	if got := len(f.items[keepass]); got != 0 {
		t.Errorf("labelled collection holds %d item(s) although a default alias exists", got)
	}
}

// TestKeyringDeleteFindsCredentialOutsideTheLoginCollection: delete must search the same collections
// the read path searches, or a credential stored anywhere but `login` becomes undeletable.
func TestKeyringDeleteFindsCredentialOutsideTheLoginCollection(t *testing.T) {
	const login = dbus.ObjectPath("/collections/login")
	const keepass = dbus.ObjectPath("/collections/keepass")

	f := newFakeSSOps()
	f.collectionList = []dbus.ObjectPath{login, keepass}
	f.labels[login] = "Login"
	f.labels[keepass] = "opencharly"
	f.addItemWithAttrs(keepass,
		map[string]string{"service": "charly/api-key", "username": "openrouter"},
		"/items/elsewhere", []byte("v"), "")

	if err := keyringDeleteViaSSClient(f, "charly/api-key", "openrouter", "opencharly"); err != nil {
		t.Fatalf("keyringDeleteViaSSClient: %v", err)
	}
	if got := len(f.items[keepass]); got != 0 {
		t.Errorf("credential survived the delete (%d item(s) left in its collection)", got)
	}
}

// TestKeyringDeleteReportsAbsenceAsNotFound keeps the caller's contract intact: KeyringStore.Delete
// tolerates ErrSSNotFound (the index entry is drift worth dropping) but must never tolerate a
// keyring it could not read.
func TestKeyringDeleteReportsAbsenceAsNotFound(t *testing.T) {
	const only = dbus.ObjectPath("/collections/only")

	f := newFakeSSOps()
	f.collectionList = []dbus.ObjectPath{only}
	f.labels[only] = "Login"

	err := keyringDeleteViaSSClient(f, "charly/secret", "NOPE", "")
	if !errors.Is(err, ErrSSNotFound) {
		t.Errorf("absent credential: err = %v, want ErrSSNotFound", err)
	}

	g := newFakeSSOps()
	g.collectionList = []dbus.ObjectPath{only}
	g.labels[only] = "Login"
	g.searchErrs[only] = errors.New("dbus: connection closed")
	err = keyringDeleteViaSSClient(g, "charly/secret", "TOK", "")
	if err == nil || errors.Is(err, ErrSSNotFound) {
		t.Errorf("unreadable keyring: err = %v, want a non-NotFound error", err)
	}
}
