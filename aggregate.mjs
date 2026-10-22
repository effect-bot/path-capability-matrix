// Merge results-*.json from the workflow artifacts into one matrix (markdown).
//   node aggregate.mjs <dir-with-results> > matrix.md
import * as fs from "node:fs"
import * as path from "node:path"

const dir = process.argv[2] ?? "."
const files = fs.readdirSync(dir, { recursive: true }).filter((f) => /results-.*\.json$/.test(f)).sort()
const runs = files.map((f) => {
  const m = /results-(ubuntu|macos|windows)-latest-(\w+)\.json$/.exec(f)
  const data = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"))
  return { os: m[1], runtime: m[2], ...data }
})
const osOrder = { ubuntu: 0, macos: 1, windows: 2 }
const rtOrder = { node20: 0, node22: 1, node24: 2, bun: 3, deno: 4 }
runs.sort((a, b) => osOrder[a.os] - osOrder[b.os] || rtOrder[a.runtime] - rtOrder[b.runtime])

const sym = { lossless: "✅", lossy: "⚠️", error: "❌", unsupported: "➖", ok: "·" }
const col = (r) => `${r.os === "ubuntu" ? "linux" : r.os}/${r.runtime}`

console.log("## Versions\n")
console.log("| job | version | node compat | libuv | platform |\n|---|---|---|---|---|")
for (const r of runs) console.log(`| ${col(r)} | ${r.versions.version} | ${r.versions.node_compat} | ${r.versions.uv ?? "-"} | ${r.versions.platform}/${r.versions.arch} ${r.versions.release} |`)

const key = (c) => `${c.group}|${c.op}|${c.input}`
const rows = new Map()
for (const r of runs) for (const c of r.cells) {
  if (!rows.has(key(c))) rows.set(key(c), { group: c.group, op: c.op, input: c.input, by: new Map() })
  rows.get(key(c)).by.set(col(r), c)
}
console.log("\n## Matrix\n\n✅ lossless · ⚠️ lossy (U+FFFD / EF BF BD) · ❌ error · ➖ unsupported / not applicable · (blank) not run on that job\n")
console.log(`| group | operation | input | ${runs.map(col).join(" | ")} |`)
console.log(`|---|---|---|${runs.map(() => "---").join("|")}|`)
for (const row of rows.values()) {
  console.log(`| ${row.group} | ${row.op} | ${row.input} | ${runs.map((r) => { const c = row.by.get(col(r)); return c ? sym[c.outcome] ?? c.outcome : "" }).join(" | ")} |`)
}

console.log("\n## Details\n")
for (const r of runs) {
  console.log(`<details><summary>${col(r)} — ${r.versions.runtime} ${r.versions.version}, uv ${r.versions.uv}</summary>\n`)
  console.log("| group | operation | input | outcome | detail |\n|---|---|---|---|---|")
  for (const c of r.cells) console.log(`| ${c.group} | ${c.op} | ${c.input} | ${sym[c.outcome] ?? ""} ${c.outcome} | ${c.detail.replaceAll("|", "\\|")} |`)
  console.log("\n</details>\n")
}
