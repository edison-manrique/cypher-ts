/**
 * @module cmac.test
 * Tests para AES-CMAC usando vectores RFC 4493
 * y validación cruzada con implementación manual sobre Node.js ECB.
 */

import { createCipheriv } from "node:crypto"
import { CMAC } from "../src/aes/cmac"
import { hexToBytes, bytesToHex } from "../src/aes/utils"

process.chdir(import.meta.dir)

const hex = { decode: hexToBytes, encode: bytesToHex }

let testCount = 0
let passCount = 0
let failCount = 0

function assertEqual(a: Uint8Array, b: Uint8Array, message: string): void {
  testCount++
  if (hex.encode(a) === hex.encode(b)) {
    passCount++
  } else {
    failCount++
    console.error(`  ✗ FAIL: ${message}`)
    console.error(`    esperado: ${hex.encode(b)}`)
    console.error(`    obtenido: ${hex.encode(a)}`)
  }
}

function assertThrows(fn: () => void, message: string): void {
  testCount++
  try {
    fn()
    failCount++
    console.error(`  ✗ FAIL: ${message} (no lanzó error)`)
  } catch {
    passCount++
  }
}

// ─── RFC 4493 Test Vectors ───────────────────────────────────────────────────
// https://www.rfc-editor.org/rfc/rfc4493.html#section-4

const RFC_KEY = hex.decode("2b7e151628aed2a6abf7158809cf4f3c")

const RFC_VECTORS = [
  {
    name: "Ejemplo 1: len = 0",
    message: "",
    expected: "bb1d6929e95937287fa37d129b756746"
  },
  {
    name: "Ejemplo 2: len = 16",
    message: "6bc1bee22e409f96e93d7e117393172a",
    expected: "070a16b46b4d4144f79bdd9dd04a287c"
  },
  {
    name: "Ejemplo 3: len = 40",
    message: "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
    expected: "dfa66747de9ae63030ca32611497c827"
  },
  {
    name: "Ejemplo 4: len = 64",
    message:
      "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
    expected: "51f0bebf7e3b9d92fc49741779363cfe"
  }
]

console.log("═══════════════════════════════════════════")
console.log("  AES-CMAC Tests")
console.log("═══════════════════════════════════════════\n")

console.log("── RFC 4493 Vectores Oficiales ──\n")

for (const vec of RFC_VECTORS) {
  console.log(`  📋 ${vec.name}`)
  const msg = vec.message ? hex.decode(vec.message) : new Uint8Array(0)
  const expected = hex.decode(vec.expected)

  // API estática
  const tag = CMAC.digest(RFC_KEY, msg)
  assertEqual(tag, expected, `${vec.name} (estática)`)

  // API incremental
  const mac = new CMAC(RFC_KEY)
  mac.update(msg)
  const tag2 = mac.digest()
  assertEqual(tag2, expected, `${vec.name} (incremental)`)

  console.log("    ✓ OK")
}

// ─── Update incremental ──────────────────────────────────────────────────────

console.log("\n── Update incremental ──\n")

{
  // Verificar que múltiples update() producen el mismo resultado que uno solo
  const msg = hex.decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
  const expected = CMAC.digest(RFC_KEY, msg)

  // Split en partes
  const mac = new CMAC(RFC_KEY)
  mac.update(msg.subarray(0, 5))
  mac.update(msg.subarray(5, 16))
  mac.update(msg.subarray(16))
  const tag = mac.digest()
  assertEqual(tag, expected, "update incremental (3 parts)")
  console.log("  ✓ Update incremental produce mismo resultado")

  // Split byte por byte
  const mac2 = new CMAC(RFC_KEY)
  for (let i = 0; i < msg.length; i++) mac2.update(msg.subarray(i, i + 1))
  const tag2 = mac2.digest()
  assertEqual(tag2, expected, "update byte-by-byte")
  console.log("  ✓ Update byte-por-byte produce mismo resultado")
}

// ─── Validación cruzada con CMAC manual (Node.js ECB) ────────────────────────

console.log("\n── Claves 128/192/256 bits (cross-validation via ECB) ──\n")

/** CMAC de referencia construido con AES-ECB de Node.js */
function nodeCmac(key: Uint8Array, msg: Uint8Array): Uint8Array {
  const alg = `aes-${key.length * 8}-ecb` as string
  function aesEncrypt(block: Uint8Array): Uint8Array {
    const c = createCipheriv(alg, key, null)
    c.setAutoPadding(false)
    return Uint8Array.from(Buffer.concat([c.update(block), c.final()]))
  }
  function dblNode(b: Uint8Array): Uint8Array {
    const r = new Uint8Array(16)
    let carry = 0
    for (let i = 15; i >= 0; i--) {
      const nc = (b[i] & 0x80) >>> 7
      r[i] = (b[i] << 1) | carry
      carry = nc
    }
    if (carry) r[15] ^= 0x87
    return r
  }
  const L = aesEncrypt(new Uint8Array(16))
  const k1 = dblNode(L)
  const k2 = dblNode(k1)
  const n = msg.length === 0 ? 1 : Math.ceil(msg.length / 16)
  const flag = msg.length > 0 && msg.length % 16 === 0
  const lastStart = (n - 1) * 16
  const lastData = msg.subarray(lastStart)
  let mLast: Uint8Array
  if (flag) {
    mLast = new Uint8Array(lastData)
    for (let i = 0; i < 16; i++) mLast[i] ^= k1[i]
  } else {
    mLast = new Uint8Array(16)
    mLast.set(lastData)
    mLast[lastData.length] = 0x80
    for (let i = 0; i < 16; i++) mLast[i] ^= k2[i]
  }
  let x = new Uint8Array(16)
  for (let i = 0; i < n - 1; i++) {
    const mi = msg.subarray(i * 16, (i + 1) * 16)
    for (let j = 0; j < 16; j++) x[j] ^= mi[j]
    x = aesEncrypt(x) as Uint8Array<ArrayBuffer>
  }
  for (let j = 0; j < 16; j++) x[j] ^= mLast[j]
  return aesEncrypt(x)
}

for (const keyLen of [16, 24, 32]) {
  const key = new Uint8Array(keyLen)
  for (let i = 0; i < keyLen; i++) key[i] = i * 3

  for (const msgLen of [0, 1, 15, 16, 17, 31, 32, 48, 64, 100, 255, 1024]) {
    const msg = new Uint8Array(msgLen)
    for (let i = 0; i < msgLen; i++) msg[i] = i & 0xff

    const nodeTag = nodeCmac(key, msg)
    const ourTag = CMAC.digest(key, msg)
    assertEqual(ourTag, nodeTag, `AES-${keyLen * 8} CMAC msg=${msgLen}`)
  }
  console.log(`  ✓ AES-${keyLen * 8}: ${12} tamaños verificados`)
}

// ─── Errores ─────────────────────────────────────────────────────────────────

console.log("\n── Validación de errores ──\n")

assertThrows(() => CMAC.digest(new Uint8Array(15), new Uint8Array(16)), "clave de 15 bytes")
console.log("  ✓ Rechaza clave de longitud inválida")

assertThrows(() => {
  const mac = new CMAC(new Uint8Array(16))
  mac.destroy()
  mac.update(new Uint8Array(1))
}, "update después de destroy")
console.log("  ✓ Rechaza update después de destroy")

assertThrows(() => {
  const mac = new CMAC(new Uint8Array(16))
  mac.destroy()
  mac.digest()
}, "digest después de destroy")
console.log("  ✓ Rechaza digest después de destroy")

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
