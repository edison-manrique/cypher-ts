/**
 * @module chacha-salsa.bench
 * Benchmark para ChaCha20, XChaCha20, Salsa20, XSalsa20.
 * Compara contra @noble/ciphers.
 */

import { ChaCha20, XChaCha20 } from "../../src/chacha"
import { Salsa20, XSalsa20 } from "../../src/salsa"
import { chacha20, xchacha20 } from "@noble/ciphers/chacha.js"
import { salsa20, xsalsa20 } from "@noble/ciphers/salsa.js"

process.chdir(import.meta.dir)

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
  return `  ${r.name.padEnd(42)} ${r.mbPerSec.toFixed(1).padStart(8)} MB/s  ${r.avgMs.toFixed(3).padStart(10)} ms/op`
}

console.log("═══════════════════════════════════════════════════════════════════════")
console.log("  ChaCha & Salsa Benchmark")
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

  console.log(`── ChaCha20 ${ds.name} ──\n`)

  const rOur = bench(`Cypher-TS ChaCha20 ${ds.name}`, ds.bytes, () => {
    new ChaCha20(key32, nonce12).encrypt(data)
  })
  const rNob = bench(`Noble ChaCha20 ${ds.name}`, ds.bytes, () => {
    chacha20(key32, nonce12, data)
  })
  console.log(fmt(rOur))
  console.log(fmt(rNob))
  console.log()

  console.log(`── XChaCha20 ${ds.name} ──\n`)

  const rOurX = bench(`Cypher-TS XChaCha20 ${ds.name}`, ds.bytes, () => {
    new XChaCha20(key32, nonce24).encrypt(data)
  })
  const rNobX = bench(`Noble XChaCha20 ${ds.name}`, ds.bytes, () => {
    xchacha20(key32, nonce24, data)
  })
  console.log(fmt(rOurX))
  console.log(fmt(rNobX))
  console.log()

  console.log(`── Salsa20 ${ds.name} ──\n`)

  const rOurS = bench(`Cypher-TS Salsa20 ${ds.name}`, ds.bytes, () => {
    new Salsa20(key32, nonce8).encrypt(data)
  })
  const rNobS = bench(`Noble Salsa20 ${ds.name}`, ds.bytes, () => {
    salsa20(key32, nonce8, data)
  })
  console.log(fmt(rOurS))
  console.log(fmt(rNobS))
  console.log()

  console.log(`── XSalsa20 ${ds.name} ──\n`)

  const rOurXS = bench(`Cypher-TS XSalsa20 ${ds.name}`, ds.bytes, () => {
    new XSalsa20(key32, nonce24).encrypt(data)
  })
  const rNobXS = bench(`Noble XSalsa20 ${ds.name}`, ds.bytes, () => {
    xsalsa20(key32, nonce24, data)
  })
  console.log(fmt(rOurXS))
  console.log(fmt(rNobXS))
  console.log()
}

console.log("═══════════════════════════════════════════════════════════════════════\n")
