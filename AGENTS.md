# AGENTS.md — plugin-secrets

Standalone plugin repo for the secrets subsystem (`verb:credential` +
`command:secrets`). The plugin is a Go module at `candy/plugin-secrets/` (module
path `github.com/opencharly/plugin-secrets/candy/plugin-secrets`); the root
`charly.yml` only declares `discover: candy` so the repo is a project and its
candy is scanned.

Canonical files:

- `candy/plugin-secrets/charly.yml` — the `plugin-secrets:` candy entity
  (`plugin:` block, `plan:` check).
- `candy/plugin-secrets/command.go` — the `charly secrets` CLI.
- `candy/plugin-secrets/store.go` / `config_store.go` / `credential_*.go` — the
  credential-store backends.
- `candy/plugin-secrets/secrets_gpg.go` — the GPG `.secrets` surface.
- `candy/plugin-secrets/schema/credential.cue` — the self-contained schema.
- `.github/workflows/tag-on-merge.yml` — CalVer tag + `CHANGELOG/` on merge.
- `README.md` — user overview only; never agent guidance.

## Load these skills first (R0)

- `/charly-internals:plugin` — the plugin authoring reference: the `plugin:`
  block, the unified Provider model, the out-of-process/CLI-syscall shape, the
  per-plugin CUE-schema contract, placement. Load before touching the provider or
  schema.
- `/charly-build:secrets` — the `charly secrets` surface, Secret Service, and GPG
  `.secrets` management this plugin owns.
- `/charly-internals:git-workflow` — before any git/PR action.

## Build / validate / test

- `go build ./...` in `candy/plugin-secrets/` — compile the plugin module.
- `go test ./...` in `candy/plugin-secrets/` — the plugin's Go tests
  (`command_test.go`, `credential_store_test.go`, `secret_service_test.go`,
  `secrets_gpg_keystore_test.go`, and the cleartext-warning / store-unavailable
  tests).
- `charly box validate` at the repo root — the structural check (the candy +
  `plugin:` block, CUE schema).
- The merge gate is the **org-wide** `charly/pr-validator` (required check
  `validate / validate`, defined in `opencharly/.github`); this repo has **no**
  per-repo candy gate.
- R10 consumer: a deploy that resolves a `secret_require`/`secret_accept` through
  the externalized store, plus a host `charly secrets` round-trip.

## Modify this repo

- Edit the `plugin-secrets:` candy entity, the Go source, and
  `schema/credential.cue` **together** — the schema is the single source for the
  `params/` struct, so a field change not mirrored in the schema desyncs the
  generated types.
- `verb:credential` is served over gRPC; `command:secrets` is served via the CLI
  `syscall.Exec` path and advertises no `Describe` capability.

## Landing

- PR-only. Every change lands through a pull request; the org-required
  `charly/pr-validator` validates the diff and body and arms native auto-merge on
  PASS. Direct pushes to `main` are blocked.
- History lives in `CHANGELOG/` (written by `tag-on-merge` at merge time); the PR
  body IS the changelog.
- The authoritative rulebook is the umbrella `AGENTS.md` in
  `opencharly/opencharly` and `charly/AGENTS.md` in the charly repo. Do not
  restate its rules here.
