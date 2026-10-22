# Path capability probe

Throwaway repo for Effect issue EFF-2776: what can Node, Bun and Deno do with
filenames that are not valid Unicode (POSIX non-UTF-8 bytes, Windows unpaired
surrogates), per filesystem operation?

- `probe.mjs` — the probe. `node probe.mjs`, `bun probe.mjs`, `deno run -A probe.mjs`.
- `oracle.py` — independent fixture creator/lister (Python bytes paths / wide-char API).
- `aggregate.mjs` — merges `results-*.json` artifacts into one matrix.
- `.github/workflows/probe.yml` — runs the probe on ubuntu/macos/windows × node20/22/24, bun, deno.
