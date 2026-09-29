# plugin-secrets

Secrets and credentials for OpenCharly — the externalized secrets subsystem.

The plugin owns the credential store (Secret Service / config-file backends) and
the GPG `.secrets` surface, so `github.com/zalando/go-keyring` lives here, out of
charly's core binary. It is served **out-of-process** — charly's loader fetches
this repo, host-builds the provider binary, and serves it over go-plugin gRPC (or
runs the host-installed `/usr/lib/charly/plugins` binary on a project-less host).

It provides two capabilities:

- **`verb:credential`** — the externalized credential-store backend (not a check
  verb). Charly forwards every `CredentialStore` method (get/set/delete/list/name),
  the env-less resolve, the doctor keyring health probe, and the keyring re-probe
  over go-plugin gRPC. Every core credential consumer resolves
  `secret_require`/`secret_accept`/VNC/`enc` passphrases exactly as before.
- **`command:secrets`** — `charly secrets …` (`list`/`get`/`set`/`delete`/`import`/
  `export`/`migrate-secrets` + the `gpg` subgroup). Charly dispatches it by
  `syscall.Exec`'ing this binary in CLI mode, so it owns real terminal stdio:
  secure password prompts, `$EDITOR` for `secrets gpg edit`, and live `gpg`
  shell-outs all reach the real terminal.

## What it provides

| Capability | Surface |
|---|---|
| `verb:credential` | the credential-store backend over gRPC |
| `command:secrets` | the `charly secrets` CLI via the `syscall.Exec` path |

## How to use it

```bash
charly secrets list
charly secrets set MY_KEY
charly secrets get MY_KEY
charly secrets gpg edit
```

## Layout

- `candy/plugin-secrets/` — the plugin module: `command.go` (the CLI),
  `store.go` / `config_store.go` / `credential_*.go` (the backends),
  `secrets_gpg.go` (the GPG `.secrets` surface), `plugin.go` / `provider.go`,
  `schema/credential.cue`, `cmd/serve/main.go`.
- `charly.yml` — the root project manifest (`discover: candy`).
- `.github/workflows/tag-on-merge.yml` — CalVer tag + `CHANGELOG/` on merge.

## Related

- Owning skill: `/charly-build:secrets` — the `charly secrets` surface, Secret
  Service, and GPG `.secrets` management this plugin owns.
- `/charly-internals:plugin` — the out-of-process plugin model.
- [`opencharly/charly`](https://github.com/opencharly/charly) — the charly CLI.
