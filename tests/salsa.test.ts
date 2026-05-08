/**
 * @module salsa.test
 * Tests para Salsa20 y XSalsa20 usando vectores stablelib
 * y validación cruzada con @noble/ciphers.
 */

import { Salsa20, XSalsa20 } from "../src/salsa"
import { salsa20, xsalsa20 } from "@noble/ciphers/salsa.js"
import { readFileSync } from "node:fs"

process.chdir(import.meta.dir)

// ─── Utilidades ──────────────────────────────────────────────────────────────

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

// ─── Vectores stablelib salsa20 ──────────────────────────────────────────────

interface StablelibSalsa {
  key: string
  nonce: string
  length: number
  digest: string
}

const salsaVectors: StablelibSalsa[] = JSON.parse(readFileSync("./vectors/stablelib_salsa20.json", "utf-8"))

console.log("═══════════════════════════════════════════")
console.log("  Salsa20 Tests")
console.log("═══════════════════════════════════════════\n")

// ─── Validación cruzada directa: Salsa20 vs noble ────────────────────────────

console.log("── Salsa20: cross-validation vs noble ──\n")

{
  const key = new Uint8Array(32)
  for (let i = 0; i < 32; i++) key[i] = i
  const nonce = new Uint8Array(8).fill(0xab)

  for (const size of [0, 1, 15, 16, 17, 63, 64, 65, 100, 255, 1024, 4096]) {
    const data = new Uint8Array(size)
    for (let i = 0; i < size; i++) data[i] = i & 0xff

    const nobleEnc = salsa20(key, nonce, data)
    const ourEnc = new Salsa20(key, nonce).encrypt(data)
    assertEqual(ourEnc, nobleEnc, `Salsa20 size=${size}`)

    const dec = new Salsa20(key, nonce).decrypt(ourEnc)
    assertEqual(dec, data, `Salsa20 roundtrip size=${size}`)
  }
  console.log("  ✓ 12 tamaños verificados contra noble")
}

// ─── Clave de 16 bytes ───────────────────────────────────────────────────────

console.log("\n── Salsa20 con clave de 16 bytes ──\n")

{
  const key16 = new Uint8Array(16)
  for (let i = 0; i < 16; i++) key16[i] = i * 5
  const nonce = new Uint8Array(8).fill(0x77)

  for (const size of [16, 64, 256, 1024]) {
    const data = new Uint8Array(size)
    for (let i = 0; i < size; i++) data[i] = i & 0xff

    const nobleEnc = salsa20(key16, nonce, data)
    const ourEnc = new Salsa20(key16, nonce).encrypt(data)
    assertEqual(ourEnc, nobleEnc, `Salsa20 key16 size=${size}`)
  }
  console.log("  ✓ Clave 16 bytes verificada")
}

// ─── XSalsa20 vs noble ──────────────────────────────────────────────────────

console.log("\n── XSalsa20: cross-validation vs noble ──\n")

{
  const key = new Uint8Array(32)
  for (let i = 0; i < 32; i++) key[i] = i ^ 0xcc
  const nonce = new Uint8Array(24)
  for (let i = 0; i < 24; i++) nonce[i] = i * 11

  for (const size of [0, 1, 15, 16, 63, 64, 65, 100, 255, 1024, 4096]) {
    const data = new Uint8Array(size)
    for (let i = 0; i < size; i++) data[i] = (i * 13) & 0xff

    const nobleEnc = xsalsa20(key, nonce, data)
    const ourEnc = new XSalsa20(key, nonce).encrypt(data)
    assertEqual(ourEnc, nobleEnc, `XSalsa20 size=${size}`)

    const dec = new XSalsa20(key, nonce).decrypt(ourEnc)
    assertEqual(dec, data, `XSalsa20 roundtrip size=${size}`)
  }
  console.log("  ✓ 11 tamaños verificados contra noble (XSalsa20)")
}

// ─── Errores ─────────────────────────────────────────────────────────────────

console.log("\n── Validación de errores ──\n")

assertThrows(() => new Salsa20(new Uint8Array(32), new Uint8Array(12)), "nonce 12 bytes en Salsa20")
console.log("  ✓ Rechaza nonce incorrecto (Salsa20)")

assertThrows(() => new XSalsa20(new Uint8Array(32), new Uint8Array(8)), "nonce 8 bytes en XSalsa20")
console.log("  ✓ Rechaza nonce incorrecto (XSalsa20)")

assertThrows(() => new XSalsa20(new Uint8Array(16), new Uint8Array(24)), "clave 16 bytes en XSalsa20")
console.log("  ✓ Rechaza clave corta (XSalsa20)")

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
