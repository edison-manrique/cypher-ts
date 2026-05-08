/**
 * @module chacha.test
 * Tests para ChaCha20 y XChaCha20 usando vectores stablelib
 * y validación cruzada con @noble/ciphers.
 */

import { ChaCha20, XChaCha20 } from "../src/chacha/index"
import { chacha20orig, xchacha20 } from "@noble/ciphers/chacha.js"
import { readFileSync } from "node:fs"

process.chdir(import.meta.dir)

// ─── Utilidades ──────────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16)
  return out
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")
}

let testCount = 0,
  passCount = 0,
  failCount = 0

function assertEqual(a: Uint8Array, b: Uint8Array, msg: string): void {
  testCount++
  if (bytesToHex(a) === bytesToHex(b)) {
    passCount++
  } else {
    failCount++
    console.error(`  ✗ FAIL: ${msg}`)
    console.error(`    esperado: ${bytesToHex(b).substring(0, 80)}...`)
    console.error(`    obtenido: ${bytesToHex(a).substring(0, 80)}...`)
  }
}

function assertThrows(fn: () => void, msg: string): void {
  testCount++
  try {
    fn()
    failCount++
    console.error(`  ✗ FAIL: ${msg} (no lanzó)`)
  } catch {
    passCount++
  }
}

// ─── Vectores stablelib (chacha20 original, nonce 8 bytes) ───────────────────

interface StablelibVector {
  key: string
  nonce: string
  stream: string
}

const chachaVectors: StablelibVector[] = JSON.parse(readFileSync("./vectors/stablelib_chacha20.json", "utf-8"))

console.log("═══════════════════════════════════════════")
console.log("  ChaCha20 Tests")
console.log("═══════════════════════════════════════════\n")

// ─── Vectores stablelib (chacha20orig = nonce 8 bytes) ───────────────────────
// Los vectores stablelib son para chacha20orig (8-byte nonce, 8-byte counter)
// Nuestra clase ChaCha20 usa RFC 8439 (12-byte nonce), así que validamos
// contra noble directamente.

console.log("── Vectores Stablelib (chacha20 orig) ──\n")

for (let i = 0; i < chachaVectors.length; i++) {
  const v = chachaVectors[i]
  const key = hexToBytes(v.key)
  const nonce = hexToBytes(v.nonce)
  const expectedStream = hexToBytes(v.stream)

  // Cifrar ceros → keystream
  const zeros = new Uint8Array(expectedStream.length)
  const nobleStream = chacha20orig(key, nonce, zeros)
  assertEqual(nobleStream, expectedStream, `stablelib vec ${i}: noble verify`)
}
console.log(`  ✓ ${chachaVectors.length} vectores stablelib verificados con noble`)

// ─── Validación cruzada: ChaCha20 RFC 8439 vs noble ──────────────────────────

console.log("\n── ChaCha20 RFC 8439: cross-validation ──\n")

{
  const key = new Uint8Array(32)
  for (let i = 0; i < 32; i++) key[i] = i
  const nonce = new Uint8Array(12).fill(0xab)

  // Noble chacha20 (RFC 8439) usa createCipher con counterLength=4
  // Importamos su versión:
  const { chacha20 } = await import("@noble/ciphers/chacha.js")

  for (const size of [0, 1, 15, 16, 17, 63, 64, 65, 100, 255, 1024, 4096]) {
    const data = new Uint8Array(size)
    for (let i = 0; i < size; i++) data[i] = i & 0xff

    const nobleEnc = chacha20(key, nonce, data)
    const ourEnc = new ChaCha20(key, nonce).encrypt(data)
    assertEqual(ourEnc, nobleEnc, `ChaCha20 RFC size=${size}`)

    // Roundtrip
    const dec = new ChaCha20(key, nonce).decrypt(ourEnc)
    assertEqual(dec, data, `ChaCha20 RFC roundtrip size=${size}`)
  }
  console.log("  ✓ 12 tamaños verificados contra noble (RFC 8439)")
}

// ─── Validación cruzada: XChaCha20 vs noble ──────────────────────────────────

console.log("\n── XChaCha20: cross-validation ──\n")

{
  const key = new Uint8Array(32)
  for (let i = 0; i < 32; i++) key[i] = i ^ 0xff
  const nonce = new Uint8Array(24)
  for (let i = 0; i < 24; i++) nonce[i] = i * 3

  for (const size of [0, 1, 15, 16, 63, 64, 65, 100, 255, 1024, 4096]) {
    const data = new Uint8Array(size)
    for (let i = 0; i < size; i++) data[i] = (i * 7) & 0xff

    const nobleEnc = xchacha20(key, nonce, data)
    const ourEnc = new XChaCha20(key, nonce).encrypt(data)
    assertEqual(ourEnc, nobleEnc, `XChaCha20 size=${size}`)

    const dec = new XChaCha20(key, nonce).decrypt(ourEnc)
    assertEqual(dec, data, `XChaCha20 roundtrip size=${size}`)
  }
  console.log("  ✓ 11 tamaños verificados contra noble (XChaCha20)")
}

// ─── Counter ─────────────────────────────────────────────────────────────────

console.log("\n── Counter offset ──\n")

{
  const { chacha20 } = await import("@noble/ciphers/chacha.js")
  const key = new Uint8Array(32).fill(0x42)
  const nonce = new Uint8Array(12).fill(0x13)
  const data = new Uint8Array(128)

  // With counter=1 (skip first block)
  const nobleEnc = chacha20(key, nonce, data, undefined, 1)
  const ourEnc = new ChaCha20(key, nonce, 1).encrypt(data)
  assertEqual(ourEnc, nobleEnc, "ChaCha20 counter=1")
  console.log("  ✓ Counter offset funciona correctamente")
}

// ─── Errors ──────────────────────────────────────────────────────────────────

console.log("\n── Validación de errores ──\n")

assertThrows(() => new ChaCha20(new Uint8Array(16), new Uint8Array(12)), "clave 16 bytes")
console.log("  ✓ Rechaza clave corta (ChaCha20)")

assertThrows(() => new ChaCha20(new Uint8Array(32), new Uint8Array(8)), "nonce 8 bytes")
console.log("  ✓ Rechaza nonce incorrecto (ChaCha20)")

assertThrows(() => new XChaCha20(new Uint8Array(32), new Uint8Array(12)), "nonce 12 bytes")
console.log("  ✓ Rechaza nonce incorrecto (XChaCha20)")

// ─── Resumen ─────────────────────────────────────────────────────────────────

console.log("\n═══════════════════════════════════════════")
console.log(`  Resultados: ${passCount}/${testCount} pasaron`)
if (failCount > 0) {
  console.log(`  ✗ ${failCount} tests fallaron`)
  process.exit(1)
} else {
  console.log("  ✓ Todos los tests pasaron")
}
console.log("═══════════════════════════════════════════\n")
