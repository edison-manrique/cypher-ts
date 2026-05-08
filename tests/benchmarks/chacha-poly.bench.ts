/**
 * @module chacha-poly.bench
 * Benchmark para ChaCha20-Poly1305 y XChaCha20-Poly1305.
 * Compara contra @noble/ciphers.
 */

import { ChaCha20Poly1305, XChaCha20Poly1305 } from "../../src/chacha/aead"
import { chacha20poly1305, xchacha20poly1305 } from "@noble/ciphers/chacha.js"

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
  return `  ${r.name.padEnd(45)} ${r.mbPerSec.toFixed(1).padStart(8)} MB/s  ${r.avgMs.toFixed(3).padStart(10)} ms/op`
}

console.log("═══════════════════════════════════════════════════════════════════════")
console.log("  ChaCha20-Poly1305 & XChaCha20-Poly1305 Benchmark")
console.log("═══════════════════════════════════════════════════════════════════════\n")

const sizes = [
  { name: "64KB", bytes: 64 * 1024 },
  { name: "1MB", bytes: 1024 * 1024 },
  { name: "10MB", bytes: 10 * 1024 * 1024 }
]

const key = new Uint8Array(32)
for (let i = 0; i < 32; i++) key[i] = i ^ 0xaa
const nonce12 = new Uint8Array(12).fill(0xbb)
const nonce24 = new Uint8Array(24).fill(0xcc)

for (const ds of sizes) {
  const data = new Uint8Array(ds.bytes)
  for (let i = 0; i < ds.bytes; i++) data[i] = i & 0xff

  // Pre-encrypt for decrypt bench
  const ourEnc = new ChaCha20Poly1305(key, nonce12).encrypt(data)
  const ourXEnc = new XChaCha20Poly1305(key, nonce24).encrypt(data)

  console.log(`── ChaCha20-Poly1305: ${ds.name} ──\n`)

  const rOurEnc = bench(`Cypher-TS Encrypt ${ds.name}`, ds.bytes, () => {
    new ChaCha20Poly1305(key, nonce12).encrypt(data)
  })
  const rOurDec = bench(`Cypher-TS Decrypt ${ds.name}`, ds.bytes, () => {
    new ChaCha20Poly1305(key, nonce12).decrypt(ourEnc)
  })
  const rNobEnc = bench(`Noble Encrypt ${ds.name}`, ds.bytes, () => {
    chacha20poly1305(key, nonce12).encrypt(data)
  })
  const rNobDec = bench(`Noble Decrypt ${ds.name}`, ds.bytes, () => {
    chacha20poly1305(key, nonce12).decrypt(ourEnc)
  })

  console.log(fmt(rOurEnc))
  console.log(fmt(rOurDec))
  console.log(fmt(rNobEnc))
  console.log(fmt(rNobDec))
  console.log()

  console.log(`── XChaCha20-Poly1305: ${ds.name} ──\n`)

  const rOurXEnc = bench(`Cypher-TS XEncrypt ${ds.name}`, ds.bytes, () => {
    new XChaCha20Poly1305(key, nonce24).encrypt(data)
  })
  const rOurXDec = bench(`Cypher-TS XDecrypt ${ds.name}`, ds.bytes, () => {
    new XChaCha20Poly1305(key, nonce24).decrypt(ourXEnc)
  })
  const rNobXEnc = bench(`Noble XEncrypt ${ds.name}`, ds.bytes, () => {
    xchacha20poly1305(key, nonce24).encrypt(data)
  })
  const rNobXDec = bench(`Noble XDecrypt ${ds.name}`, ds.bytes, () => {
    xchacha20poly1305(key, nonce24).decrypt(ourXEnc)
  })

  console.log(fmt(rOurXEnc))
  console.log(fmt(rOurXDec))
  console.log(fmt(rNobXEnc))
  console.log(fmt(rNobXDec))
  console.log()
}

console.log("═══════════════════════════════════════════════════════════════════════\n")
