/**
 * @module ff1.bench
 * Benchmark para FPE-FF1.
 * Compara Cypher-TS contra @noble/ciphers.
 */

import { FF1 } from "../../src/aes/ff1"
import { FF1 as nobleFF1 } from "@noble/ciphers/ff1.js"

process.chdir(import.meta.dir)

const WARMUP = 3
const BENCH_MS = 2000

interface BenchResult {
  name: string
  opsPerSec: number
  avgMs: number
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
    avgMs: elapsed / ops
  }
}

function fmt(r: BenchResult): string {
  return `  ${r.name.padEnd(45)} ${r.opsPerSec.toFixed(0).padStart(12)} ops/s  ${r.avgMs.toFixed(3).padStart(12)} ms/op`
}

console.log("═══════════════════════════════════════════════════════════════════════")
console.log("  FF1 Benchmark")
console.log("═══════════════════════════════════════════════════════════════════════\n")

const key = new Uint8Array(16)
for (let i = 0; i < 16; i++) key[i] = i
const tweak = new Uint8Array(8).fill(0xab)

const configs = [
  { radix: 10, len: 10, name: "radix=10, 10 dígitos (SSN)" },
  { radix: 10, len: 16, name: "radix=10, 16 dígitos (tarjeta)" },
  { radix: 36, len: 19, name: "radix=36, 19 chars (alfanum)" }
]

for (const cfg of configs) {
  const x = Array.from({ length: cfg.len }, (_, i) => i % cfg.radix)

  console.log(`── ${cfg.name} ──\n`)

  const ourEnc = new FF1(cfg.radix, key, tweak).encrypt(x)

  const rOurEnc = bench(`Cypher-TS FF1 Encrypt`, () => { new FF1(cfg.radix, key, tweak).encrypt(x) })
  const rOurDec = bench(`Cypher-TS FF1 Decrypt`, () => { new FF1(cfg.radix, key, tweak).decrypt(ourEnc) })
  const rNobEnc = bench(`Noble FF1 Encrypt`, () => { nobleFF1(cfg.radix, key, tweak).encrypt(x) })
  const rNobDec = bench(`Noble FF1 Decrypt`, () => { nobleFF1(cfg.radix, key, tweak).decrypt(ourEnc) })

  console.log(fmt(rOurEnc))
  console.log(fmt(rOurDec))
  console.log(fmt(rNobEnc))
  console.log(fmt(rNobDec))
  console.log()
}

console.log("═══════════════════════════════════════════════════════════════════════\n")
