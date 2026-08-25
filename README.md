# plugin-secrets

The `plugin-secrets` plugin candy of the [opencharly/charly](https://github.com/opencharly/charly)
candy library, as a standalone repo (the candy de-submodule cutover, plugin
kind). The Go module lives at `candy/plugin-secrets/` with module path
`github.com/opencharly/plugin-secrets/candy/plugin-secrets`; the charly resolver fetches this repo at the pinned tag and
the compiled-in wiring imports the module at that path.
