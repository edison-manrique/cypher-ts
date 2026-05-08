/**
 * @module chacha-salsa.bench
 * Benchmark para ChaCha20, XChaCha20, Salsa20, XSalsa20.
 * Compara Cypher-TS contra @noble/ciphers si está disponible.
 */

import { ChaCha20, XChaCha20 } from "../../src/chacha"
import { Salsa20, XSalsa20 } from "../../src/salsa"

process.chdir(import.meta.dir)

let nobleCh: any = null
let nobleXCh: any = null
let nobleSl: any = null
let nobleXSl: any = null
try {
  const nCh = await import("@noble/ciphers/chacha.js")
  nobleCh = nCh.chacha20
  nobleXCh = nCh.xchacha20
  const nSl = await import("@noble/ciphers/salsa.js")
  nobleSl = nSl.salsa20
  nobleXSl = nSl.xsalsa20
} catch (e) {}

const WARMUP = 3
const BENCH_MS = 2000

interface BenchResult {
  name: string
  mbPerSec: number
  avgMs: number
}

function bench(name: string, dataSize: number, fn: () => void): BenchResult {
  for (let i = 0; i < WARMUP; i++) fn()
  let ops = 0
  const start = performance.now()
  while (performance.now() - start < BENCH_MS) {
    fn()
    ops++
  }
  const elapsed = performance.now() - start
  return {
    name,
    mbPerSec: (ops * dataSize) / (elapsed / 1000) / (1024 * 1024),
    avgMs: elapsed / ops
  }
}

function fmt(r: BenchResult): string {
  return `  ${r.name.padEnd(45)} ${r.mbPerSec.toFixed(1).padStart(12)} MB/s  ${r.avgMs.toFixed(3).padStart(12)} ms/op`
}

console.log("═══════════════════════════════════════════════════════════════════════")
console.log("  ChaCha & Salsa Benchmark (64KB, 1MB, 10MB)")
console.log("═══════════════════════════════════════════════════════════════════════\n")

const sizes = [
  { name: "64KB", bytes: 64 * 1024 },
  { name: "1MB", bytes: 1024 * 1024 },
  { name: "10MB", bytes: 10 * 1024 * 1024 }
]

const key32 = new Uint8Array(32)
for (let i = 0; i < 32; i++) key32[i] = i ^ 0xaa
const nonce12 = new Uint8Array(12).fill(0xbb)
const nonce24 = new Uint8Array(24).fill(0xcc)
const nonce8 = new Uint8Array(8).fill(0xdd)

for (const ds of sizes) {
  const data = new Uint8Array(ds.bytes)
  for (let i = 0; i < ds.bytes; i++) data[i] = i & 0xff

  console.log(`── ChaCha20/Salsa20: ${ds.name} ──\n`)

  const rOurCh = bench(`Cypher-TS ChaCha20 ${ds.name}`, ds.bytes, () => { new ChaCha20(key32, nonce12).encrypt(data) })
  console.log(fmt(rOurCh))
  if (nobleCh) {
    const rNobCh = bench(`Noble ChaCha20 ${ds.name}`, ds.bytes, () => { nobleCh(key32, nonce12, data) })
    console.log(fmt(rNobCh))
  }
  
  console.log()

  const rOurXCh = bench(`Cypher-TS XChaCha20 ${ds.name}`, ds.bytes, () => { new XChaCha20(key32, nonce24).encrypt(data) })
  console.log(fmt(rOurXCh))
  if (nobleXCh) {
    const rNobXCh = bench(`Noble XChaCha20 ${ds.name}`, ds.bytes, () => { nobleXCh(key32, nonce24, data) })
    console.log(fmt(rNobXCh))
  }

  console.log()

  const rOurSl = bench(`Cypher-TS Salsa20 ${ds.name}`, ds.bytes, () => { new Salsa20(key32, nonce8).encrypt(data) })
  console.log(fmt(rOurSl))
  if (nobleSl) {
    const rNobSl = bench(`Noble Salsa20 ${ds.name}`, ds.bytes, () => { nobleSl(key32, nonce8, data) })
    console.log(fmt(rNobSl))
  }

  console.log()
}

console.log("═══════════════════════════════════════════════════════════════════════\n")
