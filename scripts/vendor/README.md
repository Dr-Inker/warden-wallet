# Vendored GitHub Actions YAML parser

`yaml-parser.mjs` is the self-contained ESM bundle of `yaml@2.8.1` used by the
first-post-checkout action-pin audit before dependencies are installed. Rebuild
it from the repository root after changing the exact `yaml` or `esbuild` pin:

```sh
pnpm exec esbuild scripts/vendor/yaml-parser.entry.mjs --bundle --platform=node --format=esm --target=node22 --minify --legal-comments=eof '--banner:js=import { createRequire } from "node:module"; const require = createRequire(import.meta.url);' --outfile=scripts/vendor/yaml-parser.mjs
```

The upstream `yaml` package is ISC licensed. Its exact locked version and
license record are covered by the repository's pnpm license-evidence gate.
