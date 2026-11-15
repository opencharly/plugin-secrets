package secrets

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
)

// ConfigFileStore implements CredentialStore using the existing plaintext
// credential maps in ~/.config/charly/config.yml. This is the fallback backend
// for headless environments without a system keyring.
type ConfigFileStore struct{}

func (c *ConfigFileStore) Get(service, key string) (string, error) {
	cfg, err := LoadRuntimeConfig()
	if err != nil {
		return "", err
	}
	return lookupConfigCredential(cfg, service, key), nil
}

func (c *ConfigFileStore) Set(service, key, value string) error {
	cfg, err := LoadRuntimeConfig()
	if err != nil {
		return err
	}
	setConfigCredential(cfg, service, key, value)
	if err := SaveRuntimeConfig(cfg); err != nil {
		return err
	}
	// Warn only after the write SUCCEEDS: the warning asserts that a secret is now sitting
	// unencrypted on disk, which is not true if the save failed.
	warnCleartextStorage(service, key)
	return nil
}

// cleartextWarnOnce keeps the warning to one per process. A single `charly config` run can store
// several secrets — an enc passphrase, a VNC password, a handful of auto-generated
// secret_require: tokens — and repeating the same paragraph for each would train operators to
// scroll past the one message that matters.
var cleartextWarnOnce sync.Once

// warnCleartextStorage reports that a secret has been persisted UNENCRYPTED.
//
// It lives HERE, at the store's write method, and nowhere else. That is deliberate and is the
// whole reason this is one warning rather than several: ConfigFileStore.Set is the single funnel
// every cleartext credential write passes through — `charly secrets set`, auto-generated
// secret_require: tokens, enc passphrases and VNC passwords alike. Warning at call sites instead
// would mean N copies drifting apart, and would miss whichever caller was added last.
//
// The trigger is CLEARTEXT REACHING DISK, never a backend name. That distinction is load-bearing:
// the common case is not an operator who pinned `secret_backend: config`, it is the DEFAULT
// `auto` falling back to this store on a host with no keyring — which a backend-name check would
// pass over in silence, warning nobody on precisely the machines that need it.
//
// Deliberately NOT warned, because none of them puts a new secret in the clear, and a false
// positive here is exactly what would make the real warning ignorable:
//   - Get/Delete/List on this store — no value is written.
//   - addKeyringIndex / removeKeyringIndex (credential_keyring.go) — they persist the keyring
//     shadow INDEX, which is service/key NAMES carrying no values.
//   - migrate-secrets (credential_admin.go) — it writes to the KEYRING and then CLEARS the
//     plaintext maps. It is the remedy for this warning, not an instance of it.
func warnCleartextStorage(service, key string) {
	cleartextWarnOnce.Do(func() {
		path, err := RuntimeConfigPath()
		if err != nil || path == "" {
			path = "~/.config/charly/config.yml"
		}
		fmt.Fprintf(os.Stderr,
			"charly: WARNING — secret stored in CLEARTEXT.\n"+
				"  %q was written unencrypted to %s (mode 0600).\n"+
				"  Any further secret stored in this run lands there in the clear too; file\n"+
				"  permissions are the only thing protecting it.\n"+
				"  To store secrets encrypted instead, run a Secret Service provider (gnome-keyring,\n"+
				"  kwalletd, or KeePassXC with FdoSecrets enabled) — charly picks it up automatically.\n"+
				"  To move what is already stored: charly secrets migrate-secrets\n",
			service+"/"+key, path)
	})
}

func (c *ConfigFileStore) Delete(service, key string) error {
	cfg, err := LoadRuntimeConfig()
	if err != nil {
		return err
	}
	deleteConfigCredential(cfg, service, key)
	return SaveRuntimeConfig(cfg)
}

func (c *ConfigFileStore) List(service string) ([]string, error) {
	cfg, err := LoadRuntimeConfig()
	if err != nil {
		return nil, err
	}
	switch service {
	case CredServiceVNC:
		if cfg.VncPasswords == nil {
			return nil, nil
		}
		keys := make([]string, 0, len(cfg.VncPasswords))
		for k := range cfg.VncPasswords {
			// Skip composite keys (belong to other services)
			if strings.Contains(k, "/") {
				continue
			}
			keys = append(keys, k)
		}
		slices.Sort(keys)
		return keys, nil
	default:
		// Non-VNC services use composite keys "service/key" in VncPasswords
		if cfg.VncPasswords == nil {
			return nil, nil
		}
		prefix := service + "/"
		keys := make([]string, 0)
		for k := range cfg.VncPasswords {
			if after, ok := strings.CutPrefix(k, prefix); ok {
				keys = append(keys, after)
			}
		}
		if len(keys) == 0 {
			return nil, nil
		}
		slices.Sort(keys)
		return keys, nil
	}
}

func (c *ConfigFileStore) Name() string {
	return "config"
}

// lookupConfigCredential reads a credential from the appropriate config map.
func lookupConfigCredential(cfg *RuntimeConfig, service, key string) string {
	if cfg.VncPasswords == nil {
		return ""
	}
	switch service {
	case CredServiceVNC:
		return cfg.VncPasswords[key]
	default:
		// Non-VNC services are stored with composite key "service/key"
		return cfg.VncPasswords[fmt.Sprintf("%s/%s", service, key)]
	}
}

// setConfigCredential writes a credential to the appropriate config map.
func setConfigCredential(cfg *RuntimeConfig, service, key, value string) {
	if cfg.VncPasswords == nil {
		cfg.VncPasswords = make(map[string]string)
	}
	switch service {
	case CredServiceVNC:
		cfg.VncPasswords[key] = value
	default:
		// Non-VNC services use composite key "service/key"
		cfg.VncPasswords[fmt.Sprintf("%s/%s", service, key)] = value
	}
}

// deleteConfigCredential removes a credential from the appropriate config map.
func deleteConfigCredential(cfg *RuntimeConfig, service, key string) {
	if cfg.VncPasswords == nil {
		return
	}
	switch service {
	case CredServiceVNC:
		delete(cfg.VncPasswords, key)
	default:
		delete(cfg.VncPasswords, fmt.Sprintf("%s/%s", service, key))
	}
}

// HasPlaintextCredentials returns the number of plaintext credentials
// currently stored in config.yml credential maps.
func HasPlaintextCredentials(cfg *RuntimeConfig) int {
	return len(cfg.VncPasswords)
}

// PlaintextCredentialEntries returns all plaintext credential entries as
// service/key pairs for migration or audit purposes.
func PlaintextCredentialEntries(cfg *RuntimeConfig) []struct{ Service, Key, Value string } {
	entries := make([]struct{ Service, Key, Value string }, 0, len(cfg.VncPasswords))
	for k, v := range cfg.VncPasswords {
		service, key := parseCompositeKey(k)
		entries = append(entries, struct{ Service, Key, Value string }{service, key, v})
	}
	return entries
}

// parseCompositeKey splits a VncPasswords map key into (service, key) — the ONE
// composite-key split in the plugin.
//
// A composite key is "<service>/<key>" and the KEY IS THE LAST SEGMENT, for every
// service: a service may itself contain slashes ("charly/secret/my-key" ->
// service="charly/secret", key="my-key"; "charly/api-key/openrouter" ->
// service="charly/api-key", key="openrouter"), while a credential key never does —
// it is an env-var name or a candy-declared slug, and neither may contain "/".
// Non-composite keys are bare VNC passwords ("my-image" -> service=CredServiceVNC).
//
// Last-slash is not a preference, it is the rule the rest of the tree already
// builds these identities with: the shadow-index reader (command.go's
// collectCredentialNames), sdk/deploykit's CollectCandySecretAccepts and
// EnsureCandySecret, and plugin-deploy-pod's secretKeyForDep all take the last
// segment as the key. A D-Bus Secret Service item's identity IS its (service,
// username) attribute pair, so a split that disagrees with the writer's does not
// merely rename a credential — it hides it. This function used to special-case two
// hard-coded prefixes and cut every other service at the FIRST slash, which stored
// "charly/api-key/<name>" as service="charly", key="api-key/<name>" and orphaned
// every credential migrated or imported under the documented shared namespace
// (opencharly/plugin-secrets#9).
func parseCompositeKey(compositeKey string) (service, key string) {
	if idx := strings.LastIndex(compositeKey, "/"); idx >= 0 {
		return compositeKey[:idx], compositeKey[idx+1:]
	}
	// No slash at all: it's a bare VNC key
	return CredServiceVNC, compositeKey
}
