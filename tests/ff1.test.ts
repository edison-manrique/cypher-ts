/**
 * @module ff1.test
 * Tests para FPE-FF1 y BinaryFF1.
 * Vectores NIST SP 800-38G + vectores BinaryFF1 + cross-validation con noble.
 */

import { FF1, BinaryFF1 } from "../src/aes/ff1"
import { FF1 as nobleFF1 } from "@noble/ciphers/ff1.js"
import { readFileSync } from "node:fs"

process.chdir(import.meta.dir)

// ─── Utilidades ──────────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  if (!hex || hex.length === 0) return new Uint8Array(0)
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

function assertArrayEq(a: number[] | Uint8Array, b: number[] | Uint8Array, msg: string): void {
  testCount++
  const aArr = Array.from(a),
    bArr = Array.from(b)
  if (aArr.length === bArr.length && aArr.every((v, i) => v === bArr[i])) {
    passCount++
  } else {
    failCount++
    console.error(`  ✗ FAIL: ${msg}`)
    console.error(`    esperado: [${bArr.join(",")}]`)
    console.error(`    obtenido: [${aArr.join(",")}]`)
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
console.log("  FF1 Tests (FPE - Format Preserving)")
console.log("═══════════════════════════════════════════\n")

// ─── Vectores NIST SP 800-38G ────────────────────────────────────────────────

console.log("── Vectores NIST SP 800-38G ──\n")

const NIST_VECTORS = [
  // AES-128
  {
    key: hexToBytes("2B7E151628AED2A6ABF7158809CF4F3C"),
    radix: 10,
    tweak: new Uint8Array(0),
    X: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    AB: [2, 4, 3, 3, 4, 7, 7, 4, 8, 4]
  },
  {
    key: hexToBytes("2B7E151628AED2A6ABF7158809CF4F3C"),
    radix: 10,
    tweak: hexToBytes("39383736353433323130"),
    X: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    AB: [6, 1, 2, 4, 2, 0, 0, 7, 7, 3]
  },
  {
    key: hexToBytes("2B7E151628AED2A6ABF7158809CF4F3C"),
    radix: 36,
    tweak: hexToBytes("3737373770717273373737"),
    X: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
    AB: [10, 9, 29, 31, 4, 0, 22, 21, 21, 9, 20, 13, 30, 5, 0, 9, 14, 30, 22]
  },
  // AES-256
  {
    key: hexToBytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"),
    radix: 10,
    tweak: new Uint8Array(0),
    X: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    AB: [6, 6, 5, 7, 6, 6, 7, 0, 0, 9]
  },
  {
    key: hexToBytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"),
    radix: 10,
    tweak: hexToBytes("39383736353433323130"),
    X: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    AB: [1, 0, 0, 1, 6, 2, 3, 4, 6, 3]
  },
  {
    key: hexToBytes("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"),
    radix: 36,
    tweak: hexToBytes("3737373770717273373737"),
    X: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
    AB: [33, 28, 8, 10, 0, 10, 35, 17, 2, 10, 31, 34, 10, 21, 34, 35, 30, 32, 13]
  }
]

for (let i = 0; i < NIST_VECTORS.length; i++) {
  const v = NIST_VECTORS[i]
  const ff1 = new FF1(v.radix, v.key, v.tweak)

  const enc = ff1.encrypt(v.X)
  assertArrayEq(enc, v.AB, `NIST vec ${i}: encrypt`)

  const dec = ff1.decrypt(v.AB)
  assertArrayEq(dec, v.X, `NIST vec ${i}: decrypt`)

  console.log(`  ✓ NIST vector ${i} (radix=${v.radix}, key=${v.key.length * 8}bit)`)
}

// ─── BinaryFF1 test ──────────────────────────────────────────────────────────

console.log("\n── BinaryFF1: test básico ──\n")

{
  const bytes = new Uint8Array([
    156, 161, 238, 80, 84, 230, 40, 147, 212, 166, 85, 71, 189, 19, 216, 222, 239, 239, 247, 244, 254, 223, 161, 182,
    178, 156, 92, 134, 113, 32, 54, 74
  ])
  const bff1 = new BinaryFF1(bytes)
  const res = bff1.encrypt(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))
  const expected = new Uint8Array([59, 246, 250, 31, 131, 191, 69, 99, 200, 167, 19])
  assertArrayEq(res, expected, "BinaryFF1 encrypt")
  console.log("  ✓ BinaryFF1 encrypt")
}

// ─── BinaryFF1 vectores ──────────────────────────────────────────────────────

console.log("\n── BinaryFF1: vectores JSON ──\n")

{
  const binVectors = JSON.parse(readFileSync("./vectors/ff1.json", "utf-8")).v
  let count = 0

  for (let i = 0; i < binVectors.length; i++) {
    const v = binVectors[i]
    if (v.data.length < 2) continue // minLen es 2 por spec

    const bff1 = new BinaryFF1(hexToBytes(v.key))
    const enc = bff1.encrypt(hexToBytes(v.data))
    assertArrayEq(enc, hexToBytes(v.exp), `BinaryFF1 vec ${i} encrypt`)

    const dec = bff1.decrypt(hexToBytes(v.exp))
    assertArrayEq(dec, hexToBytes(v.data), `BinaryFF1 vec ${i} decrypt`)
    count++
  }
  console.log(`  ✓ ${count} vectores BinaryFF1 verificados`)
}

// ─── Cross-validation con noble ──────────────────────────────────────────────

console.log("\n── Cross-validation: noble ──\n")

{
  const key = hexToBytes("2B7E151628AED2A6ABF7158809CF4F3C")

  for (const radix of [2, 10, 16, 36]) {
    // Necesitamos suficientes dígitos: radix^minLen >= 100
    const minLen = Math.ceil(Math.log(100) / Math.log(radix))
    const testLengths = [minLen, minLen + 2, minLen + 5, minLen + 10]

    for (const len of testLengths) {
      const x = Array.from({ length: len }, (_, i) => i % radix)
      const tweak = new Uint8Array(8).fill(0xab)

      const nobleEnc = nobleFF1(radix, key, tweak).encrypt(x)
      const ourEnc = new FF1(radix, key, tweak).encrypt(x)
      assertArrayEq(ourEnc, nobleEnc, `cross-val radix=${radix} len=${len} encrypt`)

      const ourDec = new FF1(radix, key, tweak).decrypt(ourEnc)
      assertArrayEq(ourDec, x, `cross-val radix=${radix} len=${len} roundtrip`)
    }
  }
  console.log("  ✓ 16 combinaciones (radix × longitud) verificadas")
}

// ─── Errores ─────────────────────────────────────────────────────────────────

console.log("\n── Validación de errores ──\n")

assertThrows(() => new FF1(1, new Uint8Array(16)).encrypt([1]), "radix=1")
console.log("  ✓ Rechaza radix < 2")

assertThrows(() => new FF1(10, new Uint8Array(16)).encrypt([1]), "X corto")
console.log("  ✓ Rechaza X demasiado corto")

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
