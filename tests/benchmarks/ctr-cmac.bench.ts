/**
 * @module ctr-cmac.bench
 * Benchmark para AES-CTR y AES-CMAC (64KB, 1MB, 10MB).
 * Compara contra Node.js crypto y @noble/ciphers.
 */

import { createCipheriv } from "node:crypto"
import { ctr as nobleCtr } from "@noble/ciphers/aes.js"
import { CTR } from "../../src/aes/ctr"
import { CMAC } from "../../src/aes/cmac"

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
  return `  ${r.name.padEnd(40)} ${r.mbPerSec.toFixed(1).padStart(8)} MB/s  ${r.avgMs.toFixed(3).padStart(10)} ms/op`
}

// ─── Benchmark ───────────────────────────────────────────────────────────────

console.log("═══════════════════════════════════════════════════════════════════════")
console.log("  AES-CTR & AES-CMAC Benchmark")
console.log("═══════════════════════════════════════════════════════════════════════\n")

const sizes = [
  { name: "64KB", bytes: 64 * 1024 },
  { name: "1MB", bytes: 1024 * 1024 },
  { name: "10MB", bytes: 10 * 1024 * 1024 }
]

const key = new Uint8Array(32)
for (let i = 0; i < 32; i++) key[i] = i ^ 0xaa
const nonce = new Uint8Array(16).fill(0xbb)

for (const ds of sizes) {
  console.log(`── CTR: ${ds.name} (AES-256) ──\n`)
  const data = new Uint8Array(ds.bytes)
  for (let i = 0; i < ds.bytes; i++) data[i] = i & 0xff

  // Nuestra lib
  const rOur = bench(`Cypher-TS CTR ${ds.name}`, ds.bytes, () => {
    new CTR(key, nonce).encrypt(data)
  })

  // Noble
  const rNob = bench(`Noble-Ciphers CTR ${ds.name}`, ds.bytes, () => {
    nobleCtr(key, nonce).encrypt(data)
  })

  // Node
  const rNod = bench(`Node.js (OpenSSL) CTR ${ds.name}`, ds.bytes, () => {
    const c = createCipheriv("aes-256-ctr", key, nonce)
    c.setAutoPadding(false)
    Buffer.concat([c.update(data), c.final()])
  })

  console.log(fmt(rOur))
  console.log(fmt(rNob))
  console.log(fmt(rNod))
  console.log()
}

// ─── CMAC ────────────────────────────────────────────────────────────────────

const key16 = key.subarray(0, 16).slice()

for (const ds of sizes) {
  console.log(`── CMAC: ${ds.name} (AES-128) ──\n`)
  const data = new Uint8Array(ds.bytes)
  for (let i = 0; i < ds.bytes; i++) data[i] = i & 0xff

  const rOur = bench(`Cypher-TS CMAC ${ds.name}`, ds.bytes, () => {
    CMAC.digest(key16, data)
  })

  console.log(fmt(rOur))
  console.log()
}

console.log("═══════════════════════════════════════════════════════════════════════\n")
