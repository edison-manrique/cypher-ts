/**
 * @module cbc.bench
 * Benchmark para AES-CBC: mide throughput de encrypt/decrypt.
 * Compara Cypher-TS contra @noble/ciphers.
 */

import { cbc as nobleCbc } from "@noble/ciphers/aes.js"
import { CBC } from "../../src/aes"

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
  return `  ${r.name.padEnd(45)} ${r.mbPerSec.toFixed(1).padStart(12)} MB/s  ${r.avgMs.toFixed(3).padStart(12)} ms/op`
}

console.log("═══════════════════════════════════════════════════════════════════════")
console.log("  AES-CBC Benchmark (64KB, 1MB, 10MB)")
console.log("═══════════════════════════════════════════════════════════════════════\n")

const sizes = [
  { name: "64KB", bytes: 64 * 1024 },
  { name: "1MB", bytes: 1024 * 1024 },
  { name: "10MB", bytes: 10 * 1024 * 1024 }
]

const key = new Uint8Array(32) // AES-256
for (let i = 0; i < 32; i++) key[i] = i ^ 0xaa
const iv = new Uint8Array(16).fill(0xab)

for (const ds of sizes) {
  const data = new Uint8Array(ds.bytes)
  for (let i = 0; i < ds.bytes; i++) data[i] = i & 0xff

  // Pre-encrypt for decrypt bench (sin padding para simplificar benchmark de core)
  const ourEnc = new CBC(key, iv, { disablePadding: true }).encrypt(data)
  const nobleEnc = nobleCbc(key, iv).encrypt(data)

  console.log(`── AES-256-CBC: ${ds.name} ──\n`)

  const rOurEnc = bench(`Cypher-TS Encrypt ${ds.name}`, ds.bytes, () => {
    new CBC(key, iv, { disablePadding: true }).encrypt(data)
  })
  const rOurDec = bench(`Cypher-TS Decrypt ${ds.name}`, ds.bytes, () => {
    new CBC(key, iv, { disablePadding: true }).decrypt(ourEnc)
  })
  const rNobEnc = bench(`Noble Encrypt ${ds.name}`, ds.bytes, () => {
    nobleCbc(key, iv).encrypt(data)
  })
  const rNobDec = bench(`Noble Decrypt ${ds.name}`, ds.bytes, () => {
    nobleCbc(key, iv).decrypt(nobleEnc)
  })

  console.log(fmt(rOurEnc))
  console.log(fmt(rOurDec))
  console.log(fmt(rNobEnc))
  console.log(fmt(rNobDec))
  console.log()
}

console.log("═══════════════════════════════════════════════════════════════════════\n")
