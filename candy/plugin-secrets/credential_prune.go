package secrets

import (
	"errors"
	"fmt"
	"os"
)

// credential_prune.go carries `charly secrets prune` — the reconciliation of the keyring SHADOW
// INDEX against the Secret Service itself.
//
// The shadow index exists because the Secret Service has no cheap list-by-service call: config.yml
// keeps a key-NAME-only list (`keyring_keys`) of what the keyring is believed to hold. A belief can
// outlive its fact — a credential deleted outside charly (another manager, a wiped collection), or
// one written under a different (service, username) pair by an older build — and the drift is
// invisible in exactly one direction: `list` and `export` are index-driven, so they keep
// advertising a credential that `get` cannot return. `KeyringStore.Get` detects that case and
// tells the operator to "Run `charly secrets prune` to reconcile", so the verb has to exist
// (opencharly/plugin-secrets#9).
//
// prune only ever drops index entries, which are NAMES: it never reads, writes or prints a secret
// value, and it never deletes a Secret Service item.
type PruneSecretsCmd struct {
	DryRun bool `name:"dry-run" help:"Report the entries that would be dropped without changing anything"`
}

// Run reconciles the index and reports every entry it touches.
func (c *PruneSecretsCmd) Run() error {
	cfg, err := LoadRuntimeConfig()
	if err != nil {
		return err
	}
	if len(cfg.KeyringKeys) == 0 {
		fmt.Fprintln(os.Stderr, "Keyring shadow index is empty — nothing to prune.")
		return nil
	}

	c2, err := newSSClient()
	if err != nil {
		// The index records KEYRING entries, so there is nothing meaningful to reconcile without
		// the keyring — and silently emptying the index would be the worst possible reading of
		// "the keyring is unavailable".
		return fmt.Errorf("Secret Service unavailable (%w) — the shadow index records keyring entries, so pruning it needs the keyring; leave it alone with `charly settings set secret_backend config` on a host without one", err)
	}
	stale, err := staleIndexEntries(c2, cfg.KeyringKeys, cfg.KeyringCollectionLabel)
	c2.close()
	if err != nil {
		return err
	}

	if len(stale) == 0 {
		fmt.Fprintf(os.Stderr, "Shadow index is consistent: all %d %s resolve in a Secret Service collection.\n",
			len(cfg.KeyringKeys), entriesNoun(len(cfg.KeyringKeys)))
		return nil
	}
	for _, entry := range stale {
		fmt.Fprintf(os.Stderr, "  %-50s → not in any collection\n", entry)
	}
	if c.DryRun {
		fmt.Fprintf(os.Stderr, "\nWould drop %d stale index %s. Run without --dry-run to drop them.\n",
			len(stale), entriesNoun(len(stale)))
		return nil
	}

	// ONE fresh read-modify-write: a `charly secrets set` that ran between the probe and this write
	// must not have the index entry it just added discarded by a stale copy of the file.
	fresh, err := LoadRuntimeConfig()
	if err != nil {
		return err
	}
	drop := make(map[string]bool, len(stale))
	for _, entry := range stale {
		drop[entry] = true
	}
	kept := make([]string, 0, len(fresh.KeyringKeys))
	for _, entry := range fresh.KeyringKeys {
		if !drop[entry] {
			kept = append(kept, entry)
		}
	}
	fresh.KeyringKeys = kept
	if err := SaveRuntimeConfig(fresh); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\nDropped %d stale index %s; %d remain.\n",
		len(stale), entriesNoun(len(stale)), len(kept))
	return nil
}

// staleIndexEntries returns the index entries whose (service, key) pair resolves in NO healthy
// Secret Service collection.
//
// ErrSSNotFound is the ONLY outcome that means "absent": the client searched at least one
// collection successfully and none held the item. Every other failure is returned as an ERROR and
// never classified as drift — reading a locked or unreachable keyring as "the credentials are gone"
// would empty the whole index over a transient condition, which is the one failure mode this verb
// must not have.
func staleIndexEntries(c ssOps, keys []string, preferLabel string) ([]string, error) {
	stale := make([]string, 0, len(keys))
	for _, entry := range keys {
		service, key := parseCompositeKey(entry)
		if service == "" || key == "" {
			continue
		}
		if _, _, ferr := findItemByAttrsAcrossCollections(c, map[string]string{"service": service, "username": key}, preferLabel); ferr != nil {
			if !errors.Is(ferr, ErrSSNotFound) {
				return nil, fmt.Errorf("reconciling %q: %w", entry, ferr)
			}
			stale = append(stale, entry)
		}
	}
	return stale, nil
}

// entriesNoun renders "entry"/"entries" so the reports read correctly at 1.
func entriesNoun(n int) string {
	if n == 1 {
		return "entry"
	}
	return "entries"
}
