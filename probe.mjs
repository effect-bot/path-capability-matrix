// Path capability probe: what can this runtime do with filenames that are not
// valid Unicode?  POSIX: a name containing byte 0xFF.  Windows: a name containing
// an unpaired surrogate U+D800.  Runs under Node, Bun and Deno.
//
//   node probe.mjs | bun probe.mjs | deno run -A probe.mjs
//
// Writes results.json (machine readable) and prints a markdown table.
import * as fs from "node:fs"
import * as fsp from "node:fs/promises"
import * as path from "node:path"
import * as os from "node:os"
import { Buffer } from "node:buffer"
import { spawnSync } from "node:child_process"
import { fileURLToPath, pathToFileURL } from "node:url"

const WIN = process.platform === "win32"
const isBun = typeof globalThis.Bun !== "undefined"
const isDeno = typeof globalThis.Deno !== "undefined"
const runtime = isBun ? "bun" : isDeno ? "deno" : "node"
const here = path.dirname(fileURLToPath(import.meta.url))
const outFile = process.env.PROBE_OUT ?? path.join(here, "results.json")

const versions = {
  runtime,
  version: isBun ? globalThis.Bun.version : isDeno ? globalThis.Deno.version.deno : process.version,
  node_compat: process.version,
  uv: process.versions?.uv ?? null,
  v8: process.versions?.v8 ?? null,
  platform: process.platform,
  arch: process.arch,
  release: os.release(),
  tmpdir: os.tmpdir()
}

// ---------------------------------------------------------------- fixtures
// Lossless identity of the bad name per OS.
//  POSIX  : bytes (Buffer).  No JS string can carry it losslessly.
//  Windows: JS string with a lone surrogate (WTF-16); bytes form is WTF-8.
const BAD_STR = WIN ? "foo\uD800.txt" : null
const BAD_BYTES = WIN ? wtf8(BAD_STR) : Buffer.from([0x66, 0x6f, 0x6f, 0xff, 0x2e, 0x74, 0x78, 0x74]) // foo\xff.txt
const BAD_DIR_STR = WIN ? "sub\uD800" : null
const BAD_DIR_BYTES = WIN ? wtf8(BAD_DIR_STR) : Buffer.from([0x73, 0x75, 0x62, 0xff]) // sub\xff
const BAD2_STR = WIN ? "bar\uD800.txt" : null
const BAD2_BYTES = WIN ? wtf8(BAD2_STR) : Buffer.from([0x62, 0x61, 0x72, 0xff, 0x2e, 0x74, 0x78, 0x74])
// What a lossy decode of the bad name looks like (U+FFFD replacement).
const LOSSY_STR = BAD_BYTES.toString("utf8")

function wtf8(str) {
  const out = []
  for (let i = 0; i < str.length; i++) {
    let c = str.charCodeAt(i)
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
      const d = str.charCodeAt(i + 1)
      if (d >= 0xdc00 && d <= 0xdfff) {
        c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00)
        i++
      }
    }
    if (c < 0x80) out.push(c)
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63))
    else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63))
    else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63))
  }
  return Buffer.from(out)
}

const esc = (s) => Array.from(s, (ch) => {
  const c = ch.codePointAt(0)
  return c < 0x20 || c > 0x7e ? "\\u{" + c.toString(16) + "}" : ch
}).join("")
const show = (v) => Buffer.isBuffer(v) || v instanceof Uint8Array ? "0x" + Buffer.from(v).toString("hex") : typeof v === "string" ? JSON.stringify(esc(v)) : String(v)

// Classify an observed name against the lossless identity.
function classifyName(observed, { bytes = BAD_BYTES, str = BAD_STR } = {}) {
  if (observed == null) return { outcome: "unsupported", detail: "no name returned" }
  if (Buffer.isBuffer(observed) || observed instanceof Uint8Array) {
    const b = Buffer.from(observed)
    if (b.equals(bytes)) return { outcome: "lossless", detail: "bytes " + show(b) }
    return { outcome: "lossy", detail: "bytes " + show(b) }
  }
  if (typeof observed === "string") {
    if (str !== null && observed === str) return { outcome: "lossless", detail: "string " + show(observed) }
    return { outcome: "lossy", detail: "string " + show(observed) }
  }
  return { outcome: "unsupported", detail: "unexpected type " + typeof observed }
}

const errOf = (e) => ({ outcome: e?.code === "NO_MATCH" ? "unsupported" : "error", detail: (e?.code ?? e?.name ?? "Error") + ": " + esc(String(e?.message ?? e).split("\n")[0].replaceAll(root, "<root>").replaceAll(here, "<here>").slice(0, 200)) })

// ---------------------------------------------------------------- oracle (python)
const python = WIN ? "python" : "python3"
function oracle(cmd, dir) {
  const r = spawnSync(python, ["-I", path.join(here, "oracle.py"), cmd, dir], { encoding: "utf8" })
  if (r.error) return { error: { strerror: String(r.error) } }
  if (r.status !== 0) return { error: { strerror: "exit " + r.status + " " + r.stderr.slice(0, 300) } }
  try { return JSON.parse(r.stdout) } catch (e) { return { error: { strerror: "bad oracle output: " + r.stdout.slice(0, 200) } } }
}
// Which lossless names exist in dir according to the oracle?  Returns Set of hex (POSIX) or string (Windows).
function oracleNames(dir) {
  const o = oracle("list", dir)
  if (o.error) return { error: o.error }
  return { names: o.entries.map((e) => WIN ? e.str : e.hex) }
}
const idOf = (bytes, str) => WIN ? str : bytes.toString("hex")
function oracleHas(dir, bytes, str) {
  const o = oracleNames(dir)
  if (o.error) return { outcome: "error", detail: "oracle: " + o.error.strerror }
  const want = idOf(bytes, str)
  if (o.names.includes(want)) return { outcome: "lossless", detail: "oracle sees exact name" }
  const lossy = o.names.find((n) => (WIN ? n.includes("�") : Buffer.from(n, "hex").toString("utf8").includes("�")) || (WIN ? false : n.includes("efbfbd")))
  if (lossy) return { outcome: "lossy", detail: "oracle sees " + (WIN ? show(lossy) : "0x" + lossy) }
  return { outcome: "lossy", detail: "oracle sees " + JSON.stringify(o.names.map((n) => WIN ? esc(n) : "0x" + n)) }
}

// ---------------------------------------------------------------- harness
const cells = []
function cell(group, op, input, r) {
  if (process.env.PROBE_TRACE) console.error(`[probe] ${group} / ${op} / ${input} -> ${r.outcome}`)
  cells.push({ group, op, input, ...r })
}
function tryCell(group, op, input, fn) {
  try {
    const r = fn()
    cell(group, op, input, r ?? { outcome: "ok", detail: "" })
  } catch (e) {
    cell(group, op, input, errOf(e))
  }
}
async function tryCellAsync(group, op, input, fn) {
  try {
    const r = await fn()
    cell(group, op, input, r ?? { outcome: "ok", detail: "" })
  } catch (e) {
    cell(group, op, input, errOf(e))
  }
}
const withTimeout = (p, ms, label) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error(label + " timeout " + ms + "ms")), ms))])
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const root = fs.mkdtempSync(path.join(os.tmpdir(), "pathprobe-"))
const fixtureDir = path.join(root, "fx")
fs.mkdirSync(fixtureDir)
const pathBytes = (dir, nameBytes) => Buffer.concat([Buffer.from(dir), Buffer.from(path.sep), nameBytes])
const pathStr = (dir, nameStr) => path.join(dir, nameStr)

const BAD_FILE_B = pathBytes(fixtureDir, BAD_BYTES)
const BAD_FILE_S = WIN ? pathStr(fixtureDir, BAD_STR) : null
const BAD_FILE_LOSSY_S = pathStr(fixtureDir, LOSSY_STR)
const BAD_DIR_B = pathBytes(fixtureDir, BAD_DIR_BYTES)

// ---------------------------------------------------------------- 0. can the filesystem hold the name at all?
const created = oracle("create", fixtureDir)
let fsSupports = !created.error
cell("fixture", "oracle create (python)", WIN ? "wide string" : "bytes", created.error
  ? { outcome: "error", detail: `errno ${created.error.errno} ${created.error.strerror}` }
  : { outcome: "lossless", detail: "python created foo<bad>.txt and sub<bad>/" })
if (fsSupports) {
  cell("fixture", "oracle list", "-", oracleHas(fixtureDir, BAD_BYTES, BAD_STR))
}

// Create via the runtime itself, in a separate dir, and ask the oracle what landed.
{
  const d = path.join(root, "create-buf")
  fs.mkdirSync(d)
  tryCell("create", "writeFileSync", "Buffer", () => {
    fs.writeFileSync(pathBytes(d, BAD_BYTES), "x")
    return oracleHas(d, BAD_BYTES, BAD_STR)
  })
  if (WIN) {
    const d2 = path.join(root, "create-str")
    fs.mkdirSync(d2)
    tryCell("create", "writeFileSync", "string(WTF-16)", () => {
      fs.writeFileSync(pathStr(d2, BAD_STR), "x")
      return oracleHas(d2, BAD_BYTES, BAD_STR)
    })
    const d3 = path.join(root, "create-url")
    fs.mkdirSync(d3)
    tryCell("create", "writeFileSync", "file URL", () => {
      fs.writeFileSync(pathToFileURL(pathStr(d3, BAD_STR)), "x")
      return oracleHas(d3, BAD_BYTES, BAD_STR)
    })
  } else {
    tryCell("create", "pathToFileURL(bytes as latin1)", "string", () => ({ outcome: "unsupported", detail: "no string form of raw bytes on POSIX" }))
  }
  tryCell("create", "mkdirSync", "Buffer", () => {
    fs.mkdirSync(pathBytes(d, BAD_DIR_BYTES))
    return oracleHas(d, BAD_DIR_BYTES, BAD_DIR_STR)
  })
  if (!fsSupports) {
    // macOS: maybe the runtime could, even though python could not?
    const o = oracleNames(d)
    fsSupports = !o.error && o.names.includes(idOf(BAD_BYTES, BAD_STR))
    if (fsSupports) {
      // use runtime-created fixtures instead
      fs.mkdirSync(path.join(fixtureDir, "unused"), { recursive: true })
      fs.writeFileSync(BAD_FILE_B, "hello")
      fs.mkdirSync(BAD_DIR_B)
    }
  }
}

if (!fsSupports) {
  cell("fixture", "all remaining operations", "-", { outcome: "unsupported", detail: "filesystem rejects the name; nothing to probe" })
} else {
  await probeAll()
}

async function probeAll() {
  // ------------------------------------------------------------ 1. path inputs
  const inputs = [["Buffer", BAD_FILE_B]]
  if (WIN) inputs.push(["string(WTF-16)", BAD_FILE_S])
  inputs.push(["string(U+FFFD)", BAD_FILE_LOSSY_S])
  if (WIN) inputs.push(["file URL", pathToFileURL(BAD_FILE_S)])

  for (const [label, p] of inputs) {
    const expectHit = label !== "string(U+FFFD)"
    const hit = (ok) => ok ? { outcome: expectHit ? "lossless" : "lossy", detail: expectHit ? "resolved the file" : "resolved a different (U+FFFD) file" } : { outcome: "lossy", detail: "resolved something else" }
    tryCell("input", "statSync", label, () => hit(fs.statSync(p).size === 5))
    tryCell("input", "accessSync", label, () => (fs.accessSync(p), hit(true)))
    tryCell("input", "existsSync", label, () => fs.existsSync(p) ? hit(true) : { outcome: "lossy", detail: "existsSync=false (name converted before syscall)" })
    tryCell("input", "openSync+readFileSync", label, () => {
      const fd = fs.openSync(p, "r")
      fs.closeSync(fd)
      return hit(fs.readFileSync(p, "utf8") === "hello")
    })
    await tryCellAsync("input", "fsp.stat", label, async () => hit((await fsp.stat(p)).size === 5))
    await tryCellAsync("input", "fsp.open", label, async () => {
      const fh = await fsp.open(p, "r")
      await fh.close()
      return hit(true)
    })
  }

  // Buffer paths through the mutating ops, verified by the oracle.
  {
    const d = path.join(root, "mut")
    fs.mkdirSync(d)
    oracle("create", d) // fixtures made by python so the runtime's own (possibly lossy) create does not mask input lossiness
    tryCell("input", "renameSync", "Buffer→Buffer", () => {
      fs.renameSync(pathBytes(d, BAD_BYTES), pathBytes(d, BAD2_BYTES))
      return oracleHas(d, BAD2_BYTES, BAD2_STR)
    })
    tryCell("input", "copyFileSync", "Buffer→Buffer", () => {
      fs.copyFileSync(pathBytes(d, BAD2_BYTES), pathBytes(d, BAD_BYTES))
      return oracleHas(d, BAD_BYTES, BAD_STR)
    })
    tryCell("input", "chmodSync", "Buffer", () => (fs.chmodSync(pathBytes(d, BAD_BYTES), 0o644), { outcome: "lossless", detail: "" }))
    tryCell("input", "utimesSync", "Buffer", () => (fs.utimesSync(pathBytes(d, BAD_BYTES), new Date(), new Date()), { outcome: "lossless", detail: "" }))
    tryCell("input", "truncateSync", "Buffer", () => (fs.truncateSync(pathBytes(d, BAD2_BYTES), 2), { outcome: "lossless", detail: "" }))
    tryCell("input", "unlinkSync", "Buffer", () => {
      fs.unlinkSync(pathBytes(d, BAD2_BYTES))
      const o = oracleNames(d)
      return o.error ? { outcome: "error", detail: o.error.strerror } : o.names.includes(idOf(BAD2_BYTES, BAD2_STR)) ? { outcome: "lossy", detail: "file still exists" } : { outcome: "lossless", detail: "oracle confirms removal" }
    })
    if (WIN) {
      tryCell("input", "renameSync", "string(WTF-16)→string(WTF-16)", () => {
        fs.renameSync(pathStr(d, BAD_STR), pathStr(d, BAD2_STR))
        return oracleHas(d, BAD2_BYTES, BAD2_STR)
      })
      tryCell("input", "unlinkSync", "string(WTF-16)", () => {
        fs.unlinkSync(pathStr(d, BAD2_STR))
        const o = oracleNames(d)
        return o.error ? { outcome: "error", detail: o.error.strerror } : o.names.includes(BAD2_STR) ? { outcome: "lossy", detail: "file still exists" } : { outcome: "lossless", detail: "oracle confirms removal" }
      })
    }
    // recursive helpers used by FileSystem.remove / copy
    const rd = path.join(root, "rmrec")
    fs.mkdirSync(rd)
    oracle("create", rd)
    const cd = path.join(root, "cprec")
    tryCell("input", "cpSync(recursive)", "string dir", () => {
      fs.cpSync(rd, cd, { recursive: true })
      const top = oracleHas(cd, BAD_BYTES, BAD_STR)
      if (top.outcome !== "lossless") return top
      return oracleHas(cd, BAD_DIR_BYTES, BAD_DIR_STR)
    })
    tryCell("input", "rmSync(recursive)", "string dir", () => {
      fs.rmSync(rd, { recursive: true, force: false })
      return fs.existsSync(rd) ? { outcome: "lossy", detail: "dir still exists after rmSync" } : { outcome: "lossless", detail: "removed tree containing bad names" }
    })
    await tryCellAsync("input", "fsp.rm(recursive)", "string dir", async () => {
      if (fs.existsSync(cd)) {
        await fsp.rm(cd, { recursive: true })
        return fs.existsSync(cd) ? { outcome: "lossy", detail: "dir still exists after rm" } : { outcome: "lossless", detail: "removed tree containing bad names" }
      }
      return { outcome: "unsupported", detail: "cpSync produced nothing to remove" }
    })
  }

  // ------------------------------------------------------------ 2. readdir / opendir
  const findBad = (names) => {
    const hit = names.find((n) => (Buffer.isBuffer(n) || n instanceof Uint8Array) ? Buffer.from(n).slice(0, 3).toString() === "foo" : typeof n === "string" && n.startsWith("foo"))
    if (hit !== undefined) return hit
    throw Object.assign(new Error("no entry starting with 'foo' in " + JSON.stringify(names.map((n) => n == null ? String(n) : typeof n === "object" && !(Buffer.isBuffer(n) || n instanceof Uint8Array) ? Object.prototype.toString.call(n) : show(n)))), { code: "NO_MATCH" })
  }
  tryCell("readdir", "readdirSync", "utf8 (default)", () => classifyName(findBad(fs.readdirSync(fixtureDir))))
  tryCell("readdir", "readdirSync", "encoding:buffer", () => classifyName(findBad(fs.readdirSync(fixtureDir, { encoding: "buffer" }))))
  tryCell("readdir", "readdirSync withFileTypes", "encoding:buffer", () => classifyName(findBad(fs.readdirSync(fixtureDir, { encoding: "buffer", withFileTypes: true }).map((d) => d.name))))
  tryCell("readdir", "readdirSync withFileTypes", "utf8", () => {
    const ds = fs.readdirSync(fixtureDir, { withFileTypes: true })
    const d = ds.find((d) => d.name.startsWith("foo"))
    const r = classifyName(d?.name)
    r.detail += `; parentPath=${d ? show(d.parentPath ?? d.path) : "?"}`
    return r
  })
  tryCell("readdir", "readdirSync recursive", "encoding:buffer", () => {
    const names = fs.readdirSync(fixtureDir, { encoding: "buffer", recursive: true })
    const r = classifyName(findBad(names))
    const nested = names.find((n) => Buffer.from(n).slice(0, 3).toString() === "sub")
    r.detail += `; nested dir entry ${nested ? show(nested) : "missing"}`
    return r
  })
  tryCell("readdir", "readdirSync recursive", "utf8", () => classifyName(findBad(fs.readdirSync(fixtureDir, { recursive: true }))))
  await tryCellAsync("readdir", "fsp.readdir", "encoding:buffer", async () => classifyName(findBad(await fsp.readdir(fixtureDir, { encoding: "buffer" }))))
  await tryCellAsync("readdir", "fsp.readdir withFileTypes", "encoding:buffer", async () => classifyName(findBad((await fsp.readdir(fixtureDir, { encoding: "buffer", withFileTypes: true })).map((d) => d.name))))
  tryCell("readdir", "opendirSync", "utf8 (default)", () => {
    const dir = fs.opendirSync(fixtureDir)
    const names = []
    for (let e; (e = dir.readSync());) names.push(e.name)
    dir.closeSync()
    return classifyName(findBad(names))
  })
  tryCell("readdir", "opendirSync", "encoding:buffer", () => {
    const dir = fs.opendirSync(fixtureDir, { encoding: "buffer", bufferSize: 32 })
    const names = []
    for (let e; (e = dir.readSync());) names.push(e.name)
    dir.closeSync()
    return classifyName(findBad(names))
  })
  await tryCellAsync("readdir", "fsp.opendir (async iter)", "encoding:buffer", async () => {
    const names = []
    for await (const e of await fsp.opendir(fixtureDir, { encoding: "buffer", bufferSize: 32 })) names.push(e.name)
    return classifyName(findBad(names))
  })

  // ------------------------------------------------------------ 3. readlink / realpath / mkdtemp
  {
    const ld = path.join(root, "links")
    fs.mkdirSync(ld)
    const target = pathBytes(ld, BAD_BYTES)
    oracle("create", ld)
    const linkRel = path.join(ld, "link-rel")
    const linkAbs = path.join(ld, "link-abs")
    // The runtime's own symlink creation, verified by the oracle, in a side dir.
    {
      const sd = path.join(root, "symlink-create")
      fs.mkdirSync(sd)
      oracle("create", sd)
      tryCell("links", "symlinkSync(target=Buffer, relative)", "Buffer", () => {
        fs.symlinkSync(BAD_BYTES, path.join(sd, "l1"), "file")
        return fs.existsSync(path.join(sd, "l1")) ? { outcome: "lossless", detail: "link resolves" } : { outcome: "lossy", detail: "dangling link (target name altered)" }
      })
      tryCell("links", "symlinkSync(target=Buffer, absolute)", "Buffer", () => {
        fs.symlinkSync(pathBytes(sd, BAD_BYTES), path.join(sd, "l2"), "file")
        return fs.existsSync(path.join(sd, "l2")) ? { outcome: "lossless", detail: "link resolves" } : { outcome: "lossy", detail: "dangling link (target name altered)" }
      })
      if (WIN) tryCell("links", "symlinkSync(target=string(WTF-16))", "string", () => {
        fs.symlinkSync(BAD_STR, path.join(sd, "l3"), "file")
        return fs.existsSync(path.join(sd, "l3")) ? { outcome: "lossless", detail: "link resolves" } : { outcome: "lossy", detail: "dangling link (target name altered)" }
      })
    }
    // Links made by the oracle, so readlink/realpath measure the runtime's output, not its symlink input handling.
    const sl = oracle("symlink", ld)
    cell("links", "oracle symlink (python)", "-", sl.error ? { outcome: "error", detail: sl.error.strerror } : { outcome: "lossless", detail: "link-rel and link-abs created by python" })
    tryCell("links", "readlinkSync", "utf8 (default)", () => classifyName(fs.readlinkSync(linkRel)))
    tryCell("links", "readlinkSync", "encoding:buffer", () => classifyName(fs.readlinkSync(linkRel, { encoding: "buffer" })))
    await tryCellAsync("links", "fsp.readlink", "encoding:buffer", async () => classifyName(await fsp.readlink(linkRel, { encoding: "buffer" })))
    const tail = (b) => Buffer.isBuffer(b) || b instanceof Uint8Array ? Buffer.from(b).subarray(Buffer.from(b).lastIndexOf(path.sep) + 1) : typeof b === "string" ? b.slice(b.lastIndexOf(path.sep) + 1) : b
    tryCell("links", "realpathSync", "Buffer in, utf8 out", () => classifyName(tail(fs.realpathSync(linkAbs))))
    tryCell("links", "realpathSync", "Buffer in, encoding:buffer", () => classifyName(tail(fs.realpathSync(linkAbs, { encoding: "buffer" }))))
    tryCell("links", "realpathSync.native", "Buffer in, encoding:buffer", () => classifyName(tail(fs.realpathSync.native(linkAbs, { encoding: "buffer" }))))
    tryCell("links", "realpathSync(Buffer path of bad file)", "Buffer in, encoding:buffer", () => classifyName(tail(fs.realpathSync(target, { encoding: "buffer" }))))
    await tryCellAsync("links", "fsp.realpath", "Buffer in, encoding:buffer", async () => classifyName(tail(await fsp.realpath(linkAbs, { encoding: "buffer" }))))
    if (WIN) {
      tryCell("links", "realpathSync.native", "string(WTF-16) in, utf8 out", () => classifyName(tail(fs.realpathSync.native(pathStr(ld, BAD_STR)))))
    }
    const td = path.join(root, "tmp")
    fs.mkdirSync(td)
    const prefixB = Buffer.concat([Buffer.from(td + path.sep), Buffer.from(WIN ? wtf8("t\uD800-") : Buffer.from([0x74, 0xff, 0x2d]))])
    const prefixBad = WIN ? wtf8("t\uD800-") : Buffer.from([0x74, 0xff, 0x2d])
    const prefixBadStr = WIN ? "t\uD800-" : null
    const checkTmp = (ret) => {
      const name = tail(ret)
      const b = Buffer.isBuffer(name) || name instanceof Uint8Array ? Buffer.from(name) : null
      const s = typeof name === "string" ? name : null
      const o = oracleNames(td)
      if (o.error) return { outcome: "error", detail: o.error.strerror }
      const onDisk = o.names.some((n) => WIN ? n.startsWith(prefixBadStr) : n.startsWith(prefixBad.toString("hex")))
      const returnedOk = b ? b.subarray(0, prefixBad.length).equals(prefixBad) : s !== null && prefixBadStr !== null && s.startsWith(prefixBadStr)
      if (onDisk && returnedOk) return { outcome: "lossless", detail: "created with exact prefix; return value matches " + show(name) }
      if (onDisk) return { outcome: "lossy", detail: "created with exact prefix but returned " + show(name) }
      return { outcome: "lossy", detail: "on disk: " + JSON.stringify(o.names.map((n) => WIN ? esc(n) : "0x" + n)) + "; returned " + show(name) }
    }
    tryCell("tmp", "mkdtempSync", "Buffer prefix, utf8 out", () => checkTmp(fs.mkdtempSync(prefixB)))
    tryCell("tmp", "mkdtempSync", "Buffer prefix, encoding:buffer", () => checkTmp(fs.mkdtempSync(prefixB, { encoding: "buffer" })))
    await tryCellAsync("tmp", "fsp.mkdtemp", "Buffer prefix, encoding:buffer", async () => checkTmp(await fsp.mkdtemp(prefixB, { encoding: "buffer" })))
    if (WIN) tryCell("tmp", "mkdtempSync", "string(WTF-16) prefix, utf8 out", () => checkTmp(fs.mkdtempSync(path.join(td, prefixBadStr))))
  }

  const touch = () => { oracle("touch", fixtureDir) }
  const pickWatched = (names) => {
    const bad = names.find((n) => n != null && ((typeof n === "string" && n.startsWith("foo")) || (!(typeof n === "string") && Buffer.from(n).subarray(0, 3).toString() === "foo")))
    if (bad === undefined) return { outcome: names.length ? "lossy" : "error", detail: names.length ? "events but no matching filename: " + names.map(show).join(",") : "no events received" }
    return classifyName(bad)
  }
  // ------------------------------------------------------------ 3b. Deno native ops (before @parcel/watcher: on Deno, loading that N-API addon makes a later Deno.watchFs hang)
  if (isDeno) {
    const D = globalThis.Deno
    const sIn = WIN ? BAD_FILE_S : BAD_FILE_LOSSY_S
    const label = WIN ? "string(WTF-16)" : "string(U+FFFD)"
    const hit = (ok) => ok ? { outcome: WIN ? "lossless" : "lossy", detail: WIN ? "resolved the file" : "resolved U+FFFD-named file?" } : { outcome: "lossy", detail: "not found" }
    await tryCellAsync("deno", "Deno.stat", label, async () => hit((await D.stat(sIn)).size === 5))
    await tryCellAsync("deno", "Deno.readTextFile", label, async () => hit((await D.readTextFile(sIn)) === "hello"))
    await tryCellAsync("deno", "Deno.readDir", "-", async () => {
      const names = []
      for await (const e of D.readDir(fixtureDir)) names.push(e.name)
      return classifyName(findBad(names))
    })
    await tryCellAsync("deno", "Deno.readLink", "-", async () => classifyName(await D.readLink(path.join(root, "links", "link-rel"))))
    await tryCellAsync("deno", "Deno.realPath", "-", async () => classifyName(path.basename(await D.realPath(path.join(root, "links", "link-abs")))))
    await tryCellAsync("deno", "Deno.makeTempDir", "prefix " + label, async () => {
      if (!WIN) return { outcome: "unsupported", detail: "string-only API; no bytes form" }
      const p = await D.makeTempDir({ dir: path.join(root, "tmp"), prefix: "d\uD800-" })
      const o = oracleNames(path.join(root, "tmp"))
      const onDisk = o.names?.some((n) => n.startsWith("d\uD800-"))
      return onDisk ? { outcome: path.basename(p).startsWith("d\uD800-") ? "lossless" : "lossy", detail: "returned " + show(path.basename(p)) } : { outcome: "lossy", detail: "on disk: " + JSON.stringify(o.names?.map(esc)) }
    })
    await tryCellAsync("deno", "Deno.writeTextFile (create)", label, async () => {
      if (!WIN) return { outcome: "unsupported", detail: "string-only API; no bytes form" }
      const d = path.join(root, "deno-create"); fs.mkdirSync(d)
      await D.writeTextFile(pathStr(d, BAD_STR), "x")
      return oracleHas(d, BAD_BYTES, BAD_STR)
    })
    await tryCellAsync("deno", "Deno.rename", label, async () => {
      if (!WIN) return { outcome: "unsupported", detail: "string-only API; no bytes form" }
      const d = path.join(root, "deno-create")
      await D.rename(pathStr(d, BAD_STR), pathStr(d, BAD2_STR))
      return oracleHas(d, BAD2_BYTES, BAD2_STR)
    })
    await tryCellAsync("deno", "Deno.remove", label, async () => {
      if (!WIN) return { outcome: "unsupported", detail: "string-only API; no bytes form" }
      const d = path.join(root, "deno-create")
      await D.remove(pathStr(d, BAD2_STR))
      const o = oracleNames(d)
      return o.names?.includes(BAD2_STR) ? { outcome: "lossy", detail: "still exists" } : { outcome: "lossless", detail: "removed" }
    })
    await tryCellAsync("deno", "Deno.watchFs", "-", async () => {
      const w = D.watchFs(fixtureDir)
      const names = []
      let failure = null
      const consume = (async () => { try { for await (const ev of w) names.push(...ev.paths.map((p) => path.basename(p))) } catch (e) { failure = e } })()
      await sleep(300); touch(); await sleep(1500); w.close()
      await withTimeout(consume, 3000, "Deno.watchFs")
      if (failure) throw failure
      return pickWatched(names)
    })
    await tryCellAsync("deno", "@std/fs walk", "-", async () => {
      const { walk } = await import("jsr:@std/fs@1")
      const names = []
      for await (const e of walk(fixtureDir, { maxDepth: 1 })) names.push(e.name)
      return classifyName(findBad(names))
    })
    await tryCellAsync("deno", "@std/fs expandGlob('*')", "-", async () => {
      const { expandGlob } = await import("jsr:@std/fs@1")
      const names = []
      for await (const e of expandGlob("*", { root: fixtureDir })) names.push(e.name)
      return classifyName(findBad(names))
    })
  }

  // ------------------------------------------------------------ 4. fs.watch and backends
  const watchOnce = (opts, trigger) => new Promise((resolve, reject) => {
    const names = []
    let w
    try {
      w = fs.watch(fixtureDir, opts, (ev, name) => { names.push(name) })
    } catch (e) { return reject(e) }
    w.on("error", reject)
    const done = () => { try { w.close() } catch {} ; resolve(names) }
    setTimeout(() => { trigger(); setTimeout(done, 1500) }, 300)
  })
  await tryCellAsync("watch", "fs.watch", "utf8 (default)", async () => pickWatched(await withTimeout(watchOnce({}, touch), 6000, "fs.watch")))
  await tryCellAsync("watch", "fs.watch", "encoding:buffer", async () => pickWatched(await withTimeout(watchOnce({ encoding: "buffer" }, touch), 6000, "fs.watch")))
  await tryCellAsync("watch", "fsp.watch (async iter)", "encoding:buffer", async () => {
    const ac = new AbortController()
    const names = []
    const it = fsp.watch(fixtureDir, { encoding: "buffer", signal: ac.signal })
    let failure = null
    const consume = (async () => { try { for await (const ev of it) names.push(ev.filename) } catch (e) { if (e?.name !== "AbortError") failure = e } })()
    await sleep(300); touch(); await sleep(1500); ac.abort()
    await withTimeout(consume, 3000, "fsp.watch")
    if (failure) throw failure
    return pickWatched(names)
  })
  // The backend NodeFileSystem used in effect 3 and the common choice for a FileSystem.WatchBackend: @parcel/watcher
  await tryCellAsync("watch", "@parcel/watcher subscribe", "string", async () => {
    const spec = isDeno ? "npm:@parcel/watcher" : "@parcel/watcher"
    const mod = await import(spec)
    const watcher = mod.default ?? mod
    const events = []
    const sub = await watcher.subscribe(fixtureDir, (err, evs) => { if (evs) events.push(...evs) })
    await sleep(1500); touch(); await sleep(500); touch(); await sleep(4000)
    await sub.unsubscribe()
    const names = events.map((e) => path.basename(e.path))
    return pickWatched(names)
  })

  // ------------------------------------------------------------ 5. glob
  tryCell("glob", "fs.globSync('*')", "cwd string", () => {
    if (typeof fs.globSync !== "function") return { outcome: "unsupported", detail: "fs.globSync not available" }
    return classifyName(findBad(fs.globSync("*", { cwd: fixtureDir })))
  })
  tryCell("glob", "fs.globSync('*', encoding:buffer)", "cwd string", () => {
    if (typeof fs.globSync !== "function") return { outcome: "unsupported", detail: "fs.globSync not available" }
    return classifyName(findBad(fs.globSync("*", { cwd: fixtureDir, encoding: "buffer" })))
  })
  tryCell("glob", "fs.globSync('**', withFileTypes)", "cwd string", () => {
    if (typeof fs.globSync !== "function") return { outcome: "unsupported", detail: "fs.globSync not available" }
    const ds = fs.globSync("**/*", { cwd: fixtureDir, withFileTypes: true })
    return classifyName(findBad(ds.map((d) => d.name)))
  })
  await tryCellAsync("glob", "fsp.glob('*')", "cwd string", async () => {
    if (typeof fsp.glob !== "function") return { outcome: "unsupported", detail: "fsp.glob not available" }
    const names = []
    for await (const n of fsp.glob("*", { cwd: fixtureDir })) names.push(n)
    return classifyName(findBad(names))
  })
  if (isBun) {
    tryCell("glob", "Bun.Glob('*').scanSync", "cwd string", () => classifyName(findBad([...new globalThis.Bun.Glob("*").scanSync({ cwd: fixtureDir })])))
    tryCell("bun", "Bun.file(string).size", WIN ? "string(WTF-16)" : "string(U+FFFD)", () => {
      const p = WIN ? BAD_FILE_S : BAD_FILE_LOSSY_S
      const size = globalThis.Bun.file(p).size
      return size === 5 ? { outcome: WIN ? "lossless" : "lossy", detail: "size=5" } : { outcome: "lossy", detail: "size=" + size }
    })
    tryCell("bun", "Bun.file(file URL).size", "file URL", () => {
      if (!WIN) return { outcome: "unsupported", detail: "no URL form of raw bytes" }
      const size = globalThis.Bun.file(pathToFileURL(BAD_FILE_S)).size
      return size === 5 ? { outcome: "lossless", detail: "size=5" } : { outcome: "lossy", detail: "size=" + size }
    })
  }

  // ------------------------------------------------------------ 7. string <-> URL conversions (no fs)
  if (WIN) {
    tryCell("convert", "pathToFileURL→fileURLToPath", "string(WTF-16)", () => classifyName(path.basename(fileURLToPath(pathToFileURL(BAD_FILE_S)))))
    tryCell("convert", "new URL(file:).pathname", "string(WTF-16)", () => ({ outcome: pathToFileURL(BAD_FILE_S).href.includes("%EF%BF%BD") ? "lossy" : "lossless", detail: pathToFileURL(BAD_FILE_S).href }))
    tryCell("convert", "Buffer.from(str,'utf8')", "string(WTF-16)", () => classifyName(Buffer.from(BAD_STR, "utf8")))
    tryCell("convert", "JSON.parse(JSON.stringify(str))", "string(WTF-16)", () => classifyName(JSON.parse(JSON.stringify(BAD_STR))))
    tryCell("convert", "encodeURIComponent(str)", "string(WTF-16)", () => ({ outcome: "lossless", detail: encodeURIComponent(BAD_STR) }))
  }
}

// ---------------------------------------------------------------- output
try { fs.rmSync(root, { recursive: true, force: true }) } catch {}
const result = { versions, cells }
fs.writeFileSync(outFile, JSON.stringify(result, null, 2))
console.log(`## ${runtime} ${versions.version} on ${process.platform} (node compat ${versions.node_compat}, uv ${versions.uv})\n`)
console.log("| group | operation | input | outcome | detail |\n|---|---|---|---|---|")
for (const c of cells) console.log(`| ${c.group} | ${c.op} | ${c.input} | **${c.outcome}** | ${c.detail.replaceAll("|", "\\|")} |`)
process.exit(0)
