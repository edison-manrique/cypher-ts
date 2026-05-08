/**
 * @module ff1.bench
 * Benchmark para FPE-FF1.
 * Compara contra @noble/ciphers.
 */

import { FF1 } from "../../src/aes/ff1"
import { FF1 as nobleFF1 } from "@noble/ciphers/ff1.js"

process.chdir(import.meta.dir)

const WARMUP = 3
const BENCH_MS = 2000

interface BenchResult {
  name: string
  opsPerSec: number
  avgUs: number
}

function bench(name: string, fn: () => void): BenchResult {
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
    opsPerSec: (ops / elapsed) * 1000,
    avgUs: (elapsed / ops) * 1000
  }
}

function fmt(r: BenchResult): string {
  return `  ${r.name.padEnd(42)} ${r.opsPerSec.toFixed(0).padStart(8)} ops/s  ${r.avgUs.toFixed(1).padStart(10)} µs/op`
}

console.log("═══════════════════════════════════════════════════════════════")
console.log("  FF1 Benchmark")
console.log("═══════════════════════════════════════════════════════════════\n")

const key = new Uint8Array(16)
for (let i = 0; i < 16; i++) key[i] = i

const configs = [
  { radix: 10, len: 10, name: "radix=10, 10 dígitos (SSN)" },
  { radix: 10, len: 16, name: "radix=10, 16 dígitos (tarjeta)" },
  { radix: 36, len: 19, name: "radix=36, 19 chars (alfanum)" },
  { radix: 10, len: 30, name: "radix=10, 30 dígitos (largo)" }
]

for (const cfg of configs) {
  const x = Array.from({ length: cfg.len }, (_, i) => i % cfg.radix)
  const tweak = new Uint8Array(8).fill(0xab)

  console.log(`── ${cfg.name} ──\n`)

  // Pre-encrypt para decrypt bench
  const ourEnc = new FF1(cfg.radix, key, tweak).encrypt(x)

  const rOurEnc = bench(`Cypher-TS FF1 encrypt`, () => {
    new FF1(cfg.radix, key, tweak).encrypt(x)
  })
  const rOurDec = bench(`Cypher-TS FF1 decrypt`, () => {
    new FF1(cfg.radix, key, tweak).decrypt(ourEnc)
  })
  const rNobEnc = bench(`Noble FF1 encrypt`, () => {
    nobleFF1(cfg.radix, key, tweak).encrypt(x)
  })
  const rNobDec = bench(`Noble FF1 decrypt`, () => {
    nobleFF1(cfg.radix, key, tweak).decrypt(ourEnc)
  })

  console.log(fmt(rOurEnc))
  console.log(fmt(rOurDec))
  console.log(fmt(rNobEnc))
  console.log(fmt(rNobDec))
  console.log()
}

console.log("═══════════════════════════════════════════════════════════════\n")
