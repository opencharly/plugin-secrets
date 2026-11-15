package secrets

import (
	"fmt"
	"os"
	"sync"
)

// credential_admin.go carries the credential-administration surface ported out of the
// core's credential_store.go: the env-then-store resolver (ResolveCredential), the
// full-reset helper (resetDefaultStore), and the `charly secrets migrate-secrets`
// command (ConfigMigrateSecretsCmd), all of which now live with the store they drive.

// ResolveCredential checks an env var override, then the credential store chain
// (resolveStoreChain, store.go). Returns the value and its source classification
// (env/keyring/config/locked/unavailable/default). The env-var precedence stays here
// (the plugin owns the whole credential resolution now); the core's pluginCredentialStore
// resolve adapter forwards only the env-LESS store chain (the host owns its OWN env).
func ResolveCredential(envVar, service, key, defaultVal string) (value, source string) {
	if envVar != "" {
		if v := os.Getenv(envVar); v != "" {
			return v, "env"
		}
	}
	v, src := resolveStoreChain(service, key)
	if v != "" {
		return v, src
	}
	return defaultVal, src
}

// resetDefaultStore resets the cached default store singleton AND the one-time
// store-info banner (the broader reset the secret_backend-change path uses). The
// store.go resetDefaultCredentialStore is the keyring-wait subset (it does NOT clear
// storeInfoOnce). Mirrors the core's former resetDefaultStore.
func resetDefaultStore() {
	defaultStoreOnce = sync.Once{}
	defaultStoreVal = nil
	defaultStoreProbeErr = nil
	storeInfoOnce = sync.Once{}
	resetKeyringState()
}

// credentialConfigKey converts a service/key pair to the dot-notation config key
// (the human-facing label the migrate-secrets report prints).
func credentialConfigKey(service, key string) string {
	switch service {
	case CredServiceVNC:
		return "vnc.password." + key
	default:
		return service + "." + key
	}
}

// ConfigMigrateSecretsCmd migrates plaintext credentials from config.yml to the system
// keyring — `charly secrets migrate-secrets` (formerly `charly settings migrate-secrets`,
// reparented under the externalized secrets CLI since it MOVES plaintext config into the
// keyring, which the plugin now owns). Unlike `charly secrets import` (which COPIES into
// the active store), this MOVES into the keyring and then strips the plaintext copies.
type ConfigMigrateSecretsCmd struct {
	DryRun bool `name:"dry-run" help:"Show what would be migrated without making changes"`
}

func (c *ConfigMigrateSecretsCmd) Run() error {
	cfg, err := LoadRuntimeConfig()
	if err != nil {
		return err
	}

	entries := PlaintextCredentialEntries(cfg)
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "No plaintext credentials found in config.yml. Nothing to migrate.")
		return nil
	}

	if c.DryRun {
		fmt.Fprintf(os.Stderr, "Found %d plaintext credential(s) in config.yml:\n\n", len(entries))
		for _, e := range entries {
			configKey := credentialConfigKey(e.Service, e.Key)
			fmt.Fprintf(os.Stderr, "  %-45s → would migrate to system keyring\n", configKey)
		}
		fmt.Fprintln(os.Stderr, "\nRun without --dry-run to migrate. A backup of config.yml will be created first.")
		return nil
	}

	// Verify keyring is usable
	keyring := &KeyringStore{}
	if err := keyring.Probe(); err != nil {
		fmt.Fprintln(os.Stderr, "Error: System keyring not available.")
		fmt.Fprintf(os.Stderr, "  Reason: %v\n\n", err)
		fmt.Fprintln(os.Stderr, "Cannot migrate credentials without a running keyring service.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fmt.Fprintln(os.Stderr, "  1. Start a keyring service (e.g., gnome-keyring-daemon --start)")
		fmt.Fprintln(os.Stderr, "  2. Install a Secret Service provider (gnome-keyring, kwalletd, keepassxc)")
		fmt.Fprintln(os.Stderr, "  3. Keep using config file: charly settings set secret_backend config")
		return fmt.Errorf("keyring not available")
	}

	// Create backup
	configPath, err := RuntimeConfigPath()
	if err != nil {
		return err
	}
	backupPath := configPath + ".bak"
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("reading config for backup: %w", err)
	}
	if err := os.WriteFile(backupPath, data, 0600); err != nil {
		return fmt.Errorf("creating backup: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Backed up config.yml to %s\n\n", backupPath)

	// Migrate each credential, tracking the ones that ACTUALLY reached the keyring. Only those
	// may leave the plaintext map: deleting the plaintext of an entry whose write failed loses
	// the credential outright, since nothing else holds it.
	fmt.Fprintf(os.Stderr, "Migrating %d credential(s):\n", len(entries))
	migrated := make([]credID, 0, len(entries))
	for _, e := range entries {
		configKey := credentialConfigKey(e.Service, e.Key)
		if err := keyring.Set(e.Service, e.Key, e.Value); err != nil {
			fmt.Fprintf(os.Stderr, "  %-45s → FAILED: %v\n", configKey, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "  %-45s → keyring ✓\n", configKey)
		migrated = append(migrated, credID{service: e.Service, key: e.Key})
	}

	if len(migrated) == 0 {
		fmt.Fprintln(os.Stderr, "\nNo credentials were migrated. Config unchanged.")
		return nil
	}

	if err := stripMigratedPlaintext(migrated); err != nil {
		fmt.Fprintf(os.Stderr, "\nWARNING: Failed to clear plaintext credentials from config: %v\n", err)
		fmt.Fprintln(os.Stderr, "Credentials were copied to keyring but plaintext copies remain.")
		return err
	}

	if left := len(entries) - len(migrated); left > 0 {
		fmt.Fprintf(os.Stderr, "\n%d credential(s) could NOT be migrated and keep their plaintext in config.yml.\n", left)
	}
	fmt.Fprintln(os.Stderr, "\nRemoved plaintext credentials from config.yml.")
	fmt.Fprintln(os.Stderr, "Migration complete. To verify: charly secrets list")
	fmt.Fprintf(os.Stderr, "To undo: cp %s %s\n", backupPath, configPath)
	return nil
}

// credID names one credential identity as it crosses the config file: the (service, key) pair the
// store resolves it by.
type credID struct{ service, key string }

// stripMigratedPlaintext deletes exactly the plaintext entries that reached the keyring, through
// ONE read-modify-write over a FRESH load.
//
// The load must be fresh: `KeyringStore.Set` appends the credential to the keyring SHADOW INDEX and
// persists config.yml on every migration step, so a `RuntimeConfig` captured before the loop holds
// a `keyring_keys` slice that predates all of them. Saving that copy back rewrote the index to its
// stale value and left every freshly migrated credential in the keyring with nothing pointing at
// it — and because `list` and `export` read the index, the store then reported "no entries" over a
// store that held them (measured on opencharly/plugin-secrets#9). Deleting only the migrated pairs
// (rather than nil-ing the whole map) also keeps the plaintext of an entry whose keyring write
// FAILED.
func stripMigratedPlaintext(migrated []credID) error {
	fresh, err := LoadRuntimeConfig()
	if err != nil {
		return fmt.Errorf("re-reading config.yml: %w", err)
	}
	for _, m := range migrated {
		deleteConfigCredential(fresh, m.service, m.key)
	}
	return SaveRuntimeConfig(fresh)
}
