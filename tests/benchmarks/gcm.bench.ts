/**
 * @module gcm.bench
 * Benchmark para AES-GCM: mide throughput de encrypt/decrypt
 * con tamaños grandes (64KB, 1MB, 10MB).
 *
 * Compara contra BunJS crypto (OpenSSL) y @noble/ciphers.
 */

import { createCipheriv, createDecipheriv } from "node:crypto"
import { gcm as nobleGcm } from "@noble/ciphers/aes.js"
import { GCM } from "../../src/aes"

process.chdir(import.meta.dir)

// ─── Configuración ───────────────────────────────────────────────────────────

const WARMUP_ITERS = 3
const BENCH_MS = 2000

interface BenchResult {
  name: string
  opsPerSec: number
  mbPerSec: number
  avgMs: number
}

function bench(name: string, dataSize: number, fn: () => void): BenchResult {
  for (let i = 0; i < WARMUP_ITERS; i++) fn()

  let ops = 0
  const start = performance.now()
  while (performance.now() - start < BENCH_MS) {
    fn()
    ops++
  }
  const elapsed = performance.now() - start
  const opsPerSec = (ops / elapsed) * 1000
  const mbPerSec = (ops * dataSize) / (elapsed / 1000) / (1024 * 1024)
  const avgMs = elapsed / ops

  return { name, opsPerSec, mbPerSec, avgMs }
}

function formatResult(r: BenchResult): string {
  return `  ${r.name.padEnd(35)} ${r.opsPerSec.toFixed(1).padStart(8)} ops/s  ${r.mbPerSec.toFixed(1).padStart(8)} MB/s  ${r.avgMs.toFixed(3).padStart(8)} ms/op`
}

// ─── Benchmark ───────────────────────────────────────────────────────────────

console.log("═══════════════════════════════════════════════════════════════════════")
console.log("  AES-GCM Benchmark (64KB, 1MB, 10MB)")
console.log("═══════════════════════════════════════════════════════════════════════\n")

// 64 KB, 1 MB, 10 MB
const dataSizes = [
  { name: "64KB", bytes: 64 * 1024 },
  { name: "1MB", bytes: 1024 * 1024 },
  { name: "10MB", bytes: 10 * 1024 * 1024 }
]

const key = new Uint8Array(32) // AES-256
for (let i = 0; i < 32; i++) key[i] = i ^ 0xaa
const nonce = new Uint8Array(12).fill(0xbb)

for (const ds of dataSizes) {
  console.log(`── Carga: ${ds.name} (AES-256-GCM) ──\n`)

  const data = new Uint8Array(ds.bytes)
  for (let i = 0; i < ds.bytes; i++) data[i] = i & 0xff

  // Pre-calcular ciphertexts de cada implementación para desencriptado
  const ourEncData = new GCM(key, nonce).encrypt(data)
  const nobleEncData = nobleGcm(key, nonce).encrypt(data)

  const c = createCipheriv("aes-256-gcm", key, nonce) as any
  const nodeEncDataBuf = Buffer.concat([c.update(data), c.final(), c.getAuthTag()])
  const nodeEncData = Uint8Array.from(nodeEncDataBuf)

  // 1. Nuestra implementación
  const rOurEnc = bench(`Cypher-TS Encrypt ${ds.name}`, ds.bytes, () => {
    new GCM(key, nonce).encrypt(data)
  })
  const rOurDec = bench(`Cypher-TS Decrypt ${ds.name}`, ds.bytes, () => {
    new GCM(key, nonce).decrypt(ourEncData)
  })

  // 2. @noble/ciphers
  const rNobEnc = bench(`Noble-Ciphers Encrypt ${ds.name}`, ds.bytes, () => {
    nobleGcm(key, nonce).encrypt(data)
  })
  const rNobDec = bench(`Noble-Ciphers Decrypt ${ds.name}`, ds.bytes, () => {
    nobleGcm(key, nonce).decrypt(nobleEncData)
  })

  // 3. BunJS
  const rNodEnc = bench(`BunJS (OpenSSL) Encrypt ${ds.name}`, ds.bytes, () => {
    const ci = createCipheriv("aes-256-gcm", key, nonce) as any
    Buffer.concat([ci.update(data), ci.final(), ci.getAuthTag()])
  })
  const rNodDec = bench(`BunJS (OpenSSL) Decrypt ${ds.name}`, ds.bytes, () => {
    const dec = createDecipheriv("aes-256-gcm", key, nonce) as any
    const ct = nodeEncData.subarray(0, -16)
    const tag = nodeEncData.subarray(-16)
    dec.setAuthTag(tag)
    Buffer.concat([dec.update(ct), dec.final()])
  })

  console.log(formatResult(rOurEnc))
  console.log(formatResult(rOurDec))
  console.log()
  console.log(formatResult(rNobEnc))
  console.log(formatResult(rNobDec))
  console.log()
  console.log(formatResult(rNodEnc))
  console.log(formatResult(rNodDec))
  console.log("\n")
}

console.log("═══════════════════════════════════════════════════════════════════════\n")
