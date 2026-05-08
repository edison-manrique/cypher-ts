/**
 * @module cbc.bench
 * Benchmark para AES-CBC: mide throughput de encrypt/decrypt
 * con distintos tamaños de clave y datos.
 *
 * Compara contra Node.js crypto (OpenSSL) como referencia.
 */

import { createCipheriv, createDecipheriv } from "node:crypto"
import { CBC } from "../../src/aes"

process.chdir(import.meta.dir)

// ─── Configuración ───────────────────────────────────────────────────────────

const WARMUP_ITERS = 50
const BENCH_MS = 2000 // duración mínima por benchmark (ms)

interface BenchResult {
  name: string
  opsPerSec: number
  mbPerSec: number
  avgNs: number
}

// ─── Utilidades ──────────────────────────────────────────────────────────────

function bench(name: string, dataSize: number, fn: () => void): BenchResult {
  // Warmup
  for (let i = 0; i < WARMUP_ITERS; i++) fn()

  // Benchmark
  let ops = 0
  const start = performance.now()
  while (performance.now() - start < BENCH_MS) {
    fn()
    ops++
  }
  const elapsed = performance.now() - start
  const opsPerSec = (ops / elapsed) * 1000
  const mbPerSec = (ops * dataSize) / (elapsed / 1000) / (1024 * 1024)
  const avgNs = (elapsed * 1e6) / ops

  return { name, opsPerSec, mbPerSec, avgNs }
}

function formatResult(r: BenchResult): string {
  return `  ${r.name.padEnd(35)} ${r.opsPerSec.toFixed(0).padStart(8)} ops/s  ${r.mbPerSec.toFixed(1).padStart(8)} MB/s  ${(r.avgNs / 1000).toFixed(1).padStart(8)} µs/op`
}

// ─── Benchmark ───────────────────────────────────────────────────────────────

console.log("═══════════════════════════════════════════════════════════════════════")
console.log("  AES-CBC Benchmark")
console.log("═══════════════════════════════════════════════════════════════════════\n")

const dataSizes = [64, 1024, 16384, 65536]
const keyConfigs = [
  { name: "AES-128", keyLen: 16, alg: "aes-128-cbc" },
  { name: "AES-256", keyLen: 32, alg: "aes-256-cbc" }
]

for (const kc of keyConfigs) {
  console.log(`── ${kc.name}-CBC ──\n`)

  const key = new Uint8Array(kc.keyLen)
  for (let i = 0; i < kc.keyLen; i++) key[i] = i
  const iv = new Uint8Array(16).fill(0xab)

  for (const size of dataSizes) {
    const data = new Uint8Array(size)
    for (let i = 0; i < size; i++) data[i] = i & 0xff

    // Pre-encrypt para decrypt benchmarks
    const ourEnc = new CBC(key, iv, { disablePadding: true }).encrypt(data)

    // Nuestra lib: encrypt
    const encResult = bench(`encrypt ${size}B`, size, () => {
      new CBC(key, iv, { disablePadding: true }).encrypt(data)
    })

    // Nuestra lib: decrypt
    const decResult = bench(`decrypt ${size}B`, size, () => {
      new CBC(key, iv, { disablePadding: true }).decrypt(ourEnc)
    })

    // Node.js crypto: encrypt (referencia)
    const nodeEncResult = bench(`node encrypt ${size}B`, size, () => {
      const c = createCipheriv(kc.alg, key, iv)
      c.setAutoPadding(false)
      Buffer.concat([c.update(data), c.final()])
    })

    // Node.js crypto: decrypt (referencia)
    const nodeDecResult = bench(`node decrypt ${size}B`, size, () => {
      const c = createDecipheriv(kc.alg, key, iv)
      c.setAutoPadding(false)
      Buffer.concat([c.update(ourEnc), c.final()])
    })

    console.log(formatResult(encResult))
    console.log(formatResult(nodeEncResult))
    console.log(formatResult(decResult))
    console.log(formatResult(nodeDecResult))
    console.log()
  }
}

console.log("═══════════════════════════════════════════════════════════════════════\n")
