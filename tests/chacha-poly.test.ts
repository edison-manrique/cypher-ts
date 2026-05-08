/**
 * @module chacha-poly.test
 * Tests para ChaCha20-Poly1305 y XChaCha20-Poly1305.
 * Usa vectores Wycheproof y validación cruzada con @noble/ciphers.
 */

import { ChaCha20Poly1305, XChaCha20Poly1305 } from "../src/chacha/aead"
import { Poly1305 } from "../src/poly1305"
import { chacha20poly1305, xchacha20poly1305 } from "@noble/ciphers/chacha.js"
import { poly1305 } from "@noble/ciphers/_poly1305.js"
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

console.log("═══════════════════════════════════════════")
console.log("  ChaCha20-Poly1305 & Poly1305 Tests")
console.log("═══════════════════════════════════════════\n")

// ─── Poly1305 standalone ─────────────────────────────────────────────────────

console.log("── Poly1305: cross-validation vs noble ──\n")

{
  for (const msgLen of [0, 1, 15, 16, 17, 31, 32, 64, 100, 255, 1024]) {
    const key = new Uint8Array(32)
    for (let i = 0; i < 32; i++) key[i] = (i * 7 + msgLen) & 0xff

    const msg = new Uint8Array(msgLen)
    for (let i = 0; i < msgLen; i++) msg[i] = (i * 13) & 0xff

    const nobleTag = poly1305(msg, key)
    const ourTag = Poly1305.mac(msg, key)
    assertEqual(ourTag, nobleTag, `Poly1305 msgLen=${msgLen}`)
  }
  console.log("  ✓ 11 tamaños verificados contra noble")
}

// ─── Wycheproof: ChaCha20-Poly1305 ──────────────────────────────────────────

console.log("\n── Wycheproof: ChaCha20-Poly1305 ──\n")

interface WycheproofTest {
  tcId: number
  comment: string
  result: "valid" | "invalid" | "acceptable"
  key: string
  iv: string
  aad: string
  msg: string
  ct: string
  tag: string
}

interface WycheproofGroup {
  ivSize: number
  keySize: number
  tagSize: number
  tests: WycheproofTest[]
}
interface WycheproofRoot {
  testGroups: WycheproofGroup[]
}

const vectors: WycheproofRoot = JSON.parse(readFileSync("./vectors/wycheproof/chacha20_poly1305_test.json", "utf-8"))

let validTests = 0,
  invalidTests = 0

for (const group of vectors.testGroups) {
  // Solo nonces de 12 bytes (ChaCha20-Poly1305 estándar)
  if (group.ivSize !== 96) continue

  for (const t of group.tests) {
    const key = hexToBytes(t.key)
    const iv = hexToBytes(t.iv)
    const aad = hexToBytes(t.aad)
    const msg = hexToBytes(t.msg)
    const ct = hexToBytes(t.ct)
    const tag = hexToBytes(t.tag)
    const combined = new Uint8Array(ct.length + tag.length)
    combined.set(ct)
    combined.set(tag, ct.length)

    if (t.result === "valid" || t.result === "acceptable") {
      try {
        const encrypted = new ChaCha20Poly1305(key, iv, aad.length > 0 ? aad : undefined).encrypt(msg)
        assertEqual(encrypted, combined, `tcId ${t.tcId} encrypt`)

        const decrypted = new ChaCha20Poly1305(key, iv, aad.length > 0 ? aad : undefined).decrypt(combined)
        assertEqual(decrypted, msg, `tcId ${t.tcId} decrypt`)
        validTests++
      } catch (e: any) {
        failCount++
        testCount++
        console.error(`  ✗ tcId ${t.tcId}: ${e.message}`)
      }
    } else if (t.result === "invalid") {
      assertThrows(() => {
        new ChaCha20Poly1305(key, iv, aad.length > 0 ? aad : undefined).decrypt(combined)
      }, `tcId ${t.tcId} (debe fallar)`)
      invalidTests++
    }
  }
}

console.log(`  Tests válidos: ${validTests}`)
console.log(`  Tests inválidos: ${invalidTests}`)

// ─── Wycheproof: XChaCha20-Poly1305 ─────────────────────────────────────────

console.log("\n── Wycheproof: XChaCha20-Poly1305 ──\n")

const xvectors: WycheproofRoot = JSON.parse(readFileSync("./vectors/wycheproof/xchacha20_poly1305_test.json", "utf-8"))

let xValid = 0,
  xInvalid = 0

for (const group of xvectors.testGroups) {
  if (group.ivSize !== 192) continue

  for (const t of group.tests) {
    const key = hexToBytes(t.key)
    const iv = hexToBytes(t.iv)
    const aad = hexToBytes(t.aad)
    const msg = hexToBytes(t.msg)
    const ct = hexToBytes(t.ct)
    const tag = hexToBytes(t.tag)
    const combined = new Uint8Array(ct.length + tag.length)
    combined.set(ct)
    combined.set(tag, ct.length)

    if (t.result === "valid" || t.result === "acceptable") {
      try {
        const encrypted = new XChaCha20Poly1305(key, iv, aad.length > 0 ? aad : undefined).encrypt(msg)
        assertEqual(encrypted, combined, `xchacha tcId ${t.tcId} encrypt`)

        const decrypted = new XChaCha20Poly1305(key, iv, aad.length > 0 ? aad : undefined).decrypt(combined)
        assertEqual(decrypted, msg, `xchacha tcId ${t.tcId} decrypt`)
        xValid++
      } catch (e: any) {
        failCount++
        testCount++
        console.error(`  ✗ xchacha tcId ${t.tcId}: ${e.message}`)
      }
    } else if (t.result === "invalid") {
      assertThrows(() => {
        new XChaCha20Poly1305(key, iv, aad.length > 0 ? aad : undefined).decrypt(combined)
      }, `xchacha tcId ${t.tcId} (debe fallar)`)
      xInvalid++
    }
  }
}

console.log(`  Tests válidos: ${xValid}`)
console.log(`  Tests inválidos: ${xInvalid}`)

// ─── Cross-validation con noble ──────────────────────────────────────────────

console.log("\n── Cross-validation: noble ──\n")

{
  const key = new Uint8Array(32)
  for (let i = 0; i < 32; i++) key[i] = i
  const nonce12 = new Uint8Array(12).fill(0xab)
  const nonce24 = new Uint8Array(24).fill(0xcd)

  for (const size of [0, 1, 15, 16, 17, 64, 100, 255, 1024, 4096]) {
    const data = new Uint8Array(size)
    for (let i = 0; i < size; i++) data[i] = i & 0xff
    const aad = new Uint8Array(size > 0 ? 16 : 0).fill(0xee)

    // ChaCha20-Poly1305
    const nobleEnc = chacha20poly1305(key, nonce12, aad.length > 0 ? aad : undefined).encrypt(data)
    const ourEnc = new ChaCha20Poly1305(key, nonce12, aad.length > 0 ? aad : undefined).encrypt(data)
    assertEqual(ourEnc, nobleEnc, `ChaCha20Poly1305 size=${size}`)

    const ourDec = new ChaCha20Poly1305(key, nonce12, aad.length > 0 ? aad : undefined).decrypt(ourEnc)
    assertEqual(ourDec, data, `ChaCha20Poly1305 roundtrip size=${size}`)

    // XChaCha20-Poly1305
    const nobleXEnc = xchacha20poly1305(key, nonce24, aad.length > 0 ? aad : undefined).encrypt(data)
    const ourXEnc = new XChaCha20Poly1305(key, nonce24, aad.length > 0 ? aad : undefined).encrypt(data)
    assertEqual(ourXEnc, nobleXEnc, `XChaCha20Poly1305 size=${size}`)

    const ourXDec = new XChaCha20Poly1305(key, nonce24, aad.length > 0 ? aad : undefined).decrypt(ourXEnc)
    assertEqual(ourXDec, data, `XChaCha20Poly1305 roundtrip size=${size}`)
  }
  console.log("  ✓ 10 tamaños verificados (ChaCha20-Poly1305 + XChaCha20-Poly1305)")
}

// ─── Errores ─────────────────────────────────────────────────────────────────

console.log("\n── Validación de errores ──\n")

assertThrows(
  () => new ChaCha20Poly1305(new Uint8Array(32), new Uint8Array(12)).decrypt(new Uint8Array(10)),
  "ciphertext corto"
)
console.log("  ✓ Rechaza ciphertext corto")

{
  const key = new Uint8Array(32).fill(1)
  const nonce = new Uint8Array(12).fill(2)
  const sealed = new ChaCha20Poly1305(key, nonce).encrypt(new Uint8Array(16))
  sealed[sealed.length - 1] ^= 0xff // Corromper tag
  assertThrows(() => new ChaCha20Poly1305(key, nonce).decrypt(sealed), "tag corrupto")
  console.log("  ✓ Detecta tag corrupto")
}

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
