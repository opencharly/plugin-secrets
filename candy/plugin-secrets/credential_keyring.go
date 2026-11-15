package secrets

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// KeyringState represents the detected state of the system keyring.
type KeyringState int

const (
	KeyringUnchecked   KeyringState = iota // Not yet probed
	KeyringAvailable                       // Unlocked and functional
	KeyringLocked                          // Present but locked (requires unlock prompt)
	KeyringUnavailable                     // Not present or broken
)

// String returns a human-readable keyring state.
func (s KeyringState) String() string {
	switch s {
	case KeyringAvailable:
		return "available"
	case KeyringLocked:
		return "locked"
	case KeyringUnavailable:
		return "unavailable"
	default:
		return "unchecked"
	}
}

var (
	keyringStateMu  sync.Mutex
	keyringStateVal KeyringState
)

// GetKeyringState returns the last detected keyring state.
func GetKeyringState() KeyringState {
	keyringStateMu.Lock()
	defer keyringStateMu.Unlock()
	return keyringStateVal
}

func setKeyringState(state KeyringState) {
	keyringStateMu.Lock()
	defer keyringStateMu.Unlock()
	keyringStateVal = state
}

// resetKeyringState resets state (for testing).
func resetKeyringState() {
	setKeyringState(KeyringUnchecked)
}

// KeyringStore implements CredentialStore using the system keyring
// (freedesktop Secret Service on Linux, Keychain on macOS).
type KeyringStore struct{}

const keyringTimeout = 3 * time.Second

// Probe tests whether the system keyring is usable.
//
// Unlike the old direct go-keyring probe (which used only the `default` alias
// and failed hard when that alias pointed at a broken collection), this
// implementation opens a direct Secret Service connection and considers the
// keyring "available" as long as at least ONE collection can be reached and
// responds to property reads. This makes charly resilient to Secret Service
// providers like KeePassXC's FdoSecrets plugin that occasionally advertise
// broken stub collections alongside working ones.
//
// Returns:
//   - nil + KeyringAvailable: at least one healthy collection exists.
//   - KeyringLockedError + KeyringLocked: the probe timed out (likely waiting
//     on an unlock prompt).
//   - plain error + KeyringUnavailable: no DBus session bus, no collections,
//     or every collection is broken.
func (k *KeyringStore) Probe() error {
	type result struct {
		healthy int
		broken  int
		err     error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := newSSClient()
		if err != nil {
			ch <- result{err: err}
			return
		}
		defer c.close()
		paths, err := c.collections()
		if err != nil {
			ch <- result{err: err}
			return
		}
		var r result
		for _, p := range paths {
			if herr := c.isCollectionHealthy(p); herr != nil {
				r.broken++
				continue
			}
			r.healthy++
		}
		if r.healthy == 0 {
			if r.broken > 0 {
				r.err = fmt.Errorf("%d collection(s) present, all broken", r.broken)
			} else {
				r.err = fmt.Errorf("no collections present")
			}
		}
		ch <- r
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			setKeyringState(KeyringUnavailable)
			return fmt.Errorf("keyring unavailable: %w", r.err)
		}
		setKeyringState(KeyringAvailable)
		return nil
	case <-time.After(keyringTimeout):
		setKeyringState(KeyringLocked)
		return fmt.Errorf("keyring probe timed out — unlock your keyring or run: charly settings set secret_backend config")
	}
}

func (k *KeyringStore) Get(service, key string) (string, error) {
	if GetKeyringState() == KeyringLocked {
		return "", &KeyringLockedError{op: "get", service: service, key: key}
	}
	type result struct {
		val string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		v, e := keyringGetViaSSClient(service, key)
		ch <- result{v, e}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			if isKeyringNotFound(r.err) {
				// Not found anywhere. Fix H: warn if the shadow index claims
				// this key should exist — something has desynchronized.
				if isIndexed, _ := isKeyringIndexed(service, key); isIndexed {
					fmt.Fprintf(os.Stderr,
						"charly: warning: %s/%s is listed in the keyring shadow index but not present in any Secret Service collection. "+
							"Run `charly secrets prune` to reconcile (or store it again with `charly secrets set %s %s`).\n",
						service, key, service, key)
				}
				return "", nil
			}
			if errors.Is(r.err, ErrSSInteractiveUnlockRequired) {
				setKeyringState(KeyringLocked)
				return "", &KeyringLockedError{op: "get", service: service, key: key}
			}
			return "", fmt.Errorf("keyring get %s/%s: %w", service, key, r.err)
		}
		return r.val, nil
	case <-time.After(keyringTimeout):
		setKeyringState(KeyringLocked)
		return "", &KeyringLockedError{op: "get", service: service, key: key}
	}
}

// keyringGetViaSSClient performs a credential read via the iteration-capable
// ssClient instead of zalando/go-keyring's hardcoded-default-alias path. This
// is the core of defect A's fix.
//
// Returns the secret value on success; ("", ErrSSNotFound) when the credential
// is not stored in any reachable collection; or a wrapped DBus error.
func keyringGetViaSSClient(service, key string) (string, error) {
	c, err := newSSClient()
	if err != nil {
		return "", fmt.Errorf("opening secret service: %w", err)
	}
	defer c.close()

	preferLabel := keyringCollectionLabel()

	item, _, err := c.findItemByAttrsAnyCollection(map[string]string{"service": service, "username": key}, preferLabel)
	if err != nil {
		return "", err
	}
	secret, err := c.getSecret(item)
	if err != nil {
		return "", fmt.Errorf("reading secret value: %w", err)
	}
	return string(secret), nil
}

// isKeyringIndexed reports whether a key is present in the shadow index
// maintained in config.yml. Used by Get to warn about index/reality drift.
func isKeyringIndexed(service, key string) (bool, error) {
	cfg, err := LoadRuntimeConfig()
	if err != nil {
		return false, err
	}
	entry := service + "/" + key
	if slices.Contains(cfg.KeyringKeys, entry) {
		return true, nil
	}
	return false, nil
}

func (k *KeyringStore) Set(service, key, value string) error {
	if GetKeyringState() == KeyringLocked {
		return &KeyringLockedError{op: "set", service: service, key: key}
	}
	ch := make(chan error, 1)
	go func() {
		c, err := newSSClient()
		if err != nil {
			ch <- fmt.Errorf("opening secret service: %w", err)
			return
		}
		defer c.close()
		ch <- keyringSetViaSSClient(c, service, key, value, keyringCollectionLabel())
	}()
	select {
	case err := <-ch:
		if err != nil {
			if errors.Is(err, ErrSSInteractiveUnlockRequired) {
				setKeyringState(KeyringLocked)
				return &KeyringLockedError{op: "set", service: service, key: key}
			}
			return fmt.Errorf("keyring set %s/%s: %w", service, key, err)
		}
		return addKeyringIndex(service, key)
	case <-time.After(keyringTimeout):
		setKeyringState(KeyringLocked)
		return &KeyringLockedError{op: "set", service: service, key: key}
	}
}

func (k *KeyringStore) Delete(service, key string) error {
	if GetKeyringState() == KeyringLocked {
		return &KeyringLockedError{op: "delete", service: service, key: key}
	}
	ch := make(chan error, 1)
	go func() {
		c, err := newSSClient()
		if err != nil {
			ch <- fmt.Errorf("opening secret service: %w", err)
			return
		}
		defer c.close()
		ch <- keyringDeleteViaSSClient(c, service, key, keyringCollectionLabel())
	}()
	select {
	case err := <-ch:
		// A miss in every collection is not an error here: the index entry (if any) is drift, and
		// dropping it is exactly what removeKeyringIndex is for.
		if err != nil && !errors.Is(err, ErrSSNotFound) {
			if errors.Is(err, ErrSSInteractiveUnlockRequired) {
				setKeyringState(KeyringLocked)
				return &KeyringLockedError{op: "delete", service: service, key: key}
			}
			return fmt.Errorf("keyring delete %s/%s: %w", service, key, err)
		}
		return removeKeyringIndex(service, key)
	case <-time.After(keyringTimeout):
		setKeyringState(KeyringLocked)
		return &KeyringLockedError{op: "delete", service: service, key: key}
	}
}

// keyringCollectionLabel returns the operator's preferred Secret Service collection label ("" =
// no preference). ONE reader, so the read, write and delete paths cannot disagree about the pin.
func keyringCollectionLabel() string {
	if cfg, err := LoadRuntimeConfig(); err == nil {
		return cfg.KeyringCollectionLabel
	}
	return ""
}

// keyringSetViaSSClient stores one credential through the iteration-capable ssClient — the SAME
// client the read path uses — so a write co-locates with the reads: it lands in the collection
// resolveTargetCollection picks (the `default` alias, else the collection labelled
// keyring_collection_label, else the first healthy unlocked one).
//
// The write path used to go through zalando/go-keyring, whose Linux provider resolves ONE
// collection — `/org/freedesktop/secrets/collection/login` when it exists, else the `default`
// alias path — and ignores `keyring_collection_label` entirely. `keyring_collection_label` is
// documented as pinning charly to a collection, and it was honoured on READS ONLY: in a
// multi-database setup (the case the config key exists for) a write landed in login/default
// instead of the database the operator chose, and a credential living in any third collection
// could not be found by Delete at all (opencharly/plugin-secrets#9).
//
// Attributes are {service, username}, the pair the read path searches on; the item label carries
// the service name, matching what the previous client wrote. createItem(replace=true) keeps the
// overwrite semantics `charly secrets set` has always had.
func keyringSetViaSSClient(c ssOps, service, key, value, preferLabel string) error {
	target, _, err := resolveTargetCollection(c, preferLabel)
	if err != nil {
		return err
	}
	_, err = c.createItem(target,
		map[string]string{"service": service, "username": key},
		[]byte(value), service, true)
	return err
}

// keyringDeleteViaSSClient removes the credential WHEREVER it lives. Delete used the same
// one-collection resolution as the old write path, and a not-found was indistinguishable from a
// successful delete, so `charly secrets delete` on a credential stored in any other collection
// printed "Deleted … from keyring", dropped its shadow-index entry, and left the item in the store
// — the operator losing the only pointer to it (opencharly/plugin-secrets#9).
func keyringDeleteViaSSClient(c ssOps, service, key, preferLabel string) error {
	item, _, err := findItemByAttrsAcrossCollections(c,
		map[string]string{"service": service, "username": key}, preferLabel)
	if err != nil {
		return err
	}
	return c.deleteItem(item)
}

// List returns all keys for a service from the shadow index.
// The Secret Service has no cheap list-by-service call, so we maintain
// a key-name-only index in config.yml (no secret values stored).
func (k *KeyringStore) List(service string) ([]string, error) {
	cfg, err := LoadRuntimeConfig()
	if err != nil {
		return nil, err
	}
	prefix := service + "/"
	var keys []string
	for _, entry := range cfg.KeyringKeys {
		if after, ok := strings.CutPrefix(entry, prefix); ok {
			keys = append(keys, after)
		}
	}
	return keys, nil
}

func (k *KeyringStore) Name() string {
	if GetKeyringState() == KeyringLocked {
		return "keyring (locked)"
	}
	return "keyring"
}

// KeyringLockedError is returned when a keyring operation cannot proceed
// because the keyring is locked. Callers can check for this with
// errors.As to provide context-specific messages.
type KeyringLockedError struct {
	op      string // "get", "set", "delete"
	service string
	key     string
}

func (e *KeyringLockedError) Error() string {
	return fmt.Sprintf("keyring is locked (cannot %s %s/%s) — unlock your keyring or run: charly settings set secret_backend config", e.op, e.service, e.key)
}

// IsKeyringLocked returns true if the error is a KeyringLockedError.
func IsKeyringLocked(err error) bool {
	var locked *KeyringLockedError
	return err != nil && errors.As(err, &locked)
}

// isKeyringNotFound checks whether the error indicates the key was not found: ErrSSNotFound from
// our ssClient, which is an AUTHORITATIVE miss — at least one collection was searched successfully
// and none holds the item. A broken or locked collection reports ErrSSAllBroken /
// ErrSSInteractiveUnlockRequired instead, so "the keyring could not be read" is never mistaken for
// "the credential is absent".
func isKeyringNotFound(err error) bool {
	return err != nil && errors.Is(err, ErrSSNotFound)
}

// addKeyringIndex adds a service/key entry to the shadow index in config.yml.
func addKeyringIndex(service, key string) error {
	cfg, err := LoadRuntimeConfig()
	if err != nil {
		return err
	}
	entry := service + "/" + key
	if slices.Contains(cfg.KeyringKeys, entry) {
		return nil
	}
	cfg.KeyringKeys = append(cfg.KeyringKeys, entry)
	slices.Sort(cfg.KeyringKeys)
	return SaveRuntimeConfig(cfg)
}

// removeKeyringIndex removes a service/key entry from the shadow index.
func removeKeyringIndex(service, key string) error {
	cfg, err := LoadRuntimeConfig()
	if err != nil {
		return err
	}
	entry := service + "/" + key
	idx := slices.Index(cfg.KeyringKeys, entry)
	if idx < 0 {
		return nil
	}
	cfg.KeyringKeys = slices.Delete(cfg.KeyringKeys, idx, idx+1)
	return SaveRuntimeConfig(cfg)
}
