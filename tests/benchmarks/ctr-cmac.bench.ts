/**
 * @module ctr-cmac.bench
 * Benchmark para AES-CTR y AES-CMAC.
 * Compara Cypher-TS contra @noble/ciphers.
 */

import { ctr as nobleCtr, cmac as nobleCmac } from "@noble/ciphers/aes.js"
import { CTR } from "../../src/aes/ctr"
import { CMAC } from "../../src/aes/cmac"

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
console.log("  AES-CTR & AES-CMAC Benchmark (64KB, 1MB, 10MB)")
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
  const data = new Uint8Array(ds.bytes)
  for (let i = 0; i < ds.bytes; i++) data[i] = i & 0xff

  console.log(`── AES-256-CTR: ${ds.name} ──\n`)

  const rOur = bench(`Cypher-TS CTR ${ds.name}`, ds.bytes, () => {
    new CTR(key, nonce).encrypt(data)
  })
  const rNob = bench(`Noble CTR ${ds.name}`, ds.bytes, () => {
    nobleCtr(key, nonce).encrypt(data)
  })

  console.log(fmt(rOur))
  console.log(fmt(rNob))
  console.log()
}

console.log("-----------------------------------------------------------------------\n")

for (const ds of sizes) {
  const data = new Uint8Array(ds.bytes)
  for (let i = 0; i < ds.bytes; i++) data[i] = i & 0xff

  console.log(`── AES-128-CMAC: ${ds.name} ──\n`)

  const key16 = key.subarray(0, 16)
  const rOur = bench(`Cypher-TS CMAC ${ds.name}`, ds.bytes, () => {
    CMAC.digest(key16, data)
  })
  const rNob = bench(`Noble CMAC ${ds.name}`, ds.bytes, () => {
    nobleCmac(key16, data)
  })

  console.log(fmt(rOur))
  console.log(fmt(rNob))
  console.log()
}

console.log("═══════════════════════════════════════════════════════════════════════\n")
