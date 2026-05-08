/**
 * @module ctr.test
 * Tests para AES-CTR usando vectores NIST SP 800-38A
 * y validación cruzada con Node.js crypto.
 */

import { createCipheriv, createDecipheriv } from "node:crypto"
import { CTR } from "../src/aes/ctr"
import { hexToBytes, bytesToHex, concatBytes } from "../src/aes/utils"

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

// ─── NIST SP 800-38A F.5 ─────────────────────────────────────────────────────

interface NistVector {
  name: string
  key: string
  nonce: string
  blocks: { plaintext: string; ciphertext: string }[]
}

const NIST_CTR_VECTORS: NistVector[] = [
  {
    name: "CTR-AES128",
    key: "2b7e151628aed2a6abf7158809cf4f3c",
    nonce: "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    blocks: [
      { plaintext: "6bc1bee22e409f96e93d7e117393172a", ciphertext: "874d6191b620e3261bef6864990db6ce" },
      { plaintext: "ae2d8a571e03ac9c9eb76fac45af8e51", ciphertext: "9806f66b7970fdff8617187bb9fffdff" },
      { plaintext: "30c81c46a35ce411e5fbc1191a0a52ef", ciphertext: "5ae4df3edbd5d35e5b4f09020db03eab" },
      { plaintext: "f69f2445df4f9b17ad2b417be66c3710", ciphertext: "1e031dda2fbe03d1792170a0f3009cee" }
    ]
  },
  {
    name: "CTR-AES192",
    key: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
    nonce: "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    blocks: [
      { plaintext: "6bc1bee22e409f96e93d7e117393172a", ciphertext: "1abc932417521ca24f2b0459fe7e6e0b" },
      { plaintext: "ae2d8a571e03ac9c9eb76fac45af8e51", ciphertext: "090339ec0aa6faefd5ccc2c6f4ce8e94" },
      { plaintext: "30c81c46a35ce411e5fbc1191a0a52ef", ciphertext: "1e36b26bd1ebc670d1bd1d665620abf7" },
      { plaintext: "f69f2445df4f9b17ad2b417be66c3710", ciphertext: "4f78a7f6d29809585a97daec58c6b050" }
    ]
  },
  {
    name: "CTR-AES256",
    key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
    nonce: "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    blocks: [
      { plaintext: "6bc1bee22e409f96e93d7e117393172a", ciphertext: "601ec313775789a5b7a7f504bbf3d228" },
      { plaintext: "ae2d8a571e03ac9c9eb76fac45af8e51", ciphertext: "f443e3ca4d62b59aca84e990cacaf5c5" },
      { plaintext: "30c81c46a35ce411e5fbc1191a0a52ef", ciphertext: "2b0930daa23de94ce87017ba2d84988d" },
      { plaintext: "f69f2445df4f9b17ad2b417be66c3710", ciphertext: "dfc9c58db67aada613c2dd08457941a6" }
    ]
  }
]

console.log("═══════════════════════════════════════════")
console.log("  AES-CTR Tests")
console.log("═══════════════════════════════════════════\n")

console.log("── NIST SP 800-38A Vectores ──\n")

for (const vec of NIST_CTR_VECTORS) {
  console.log(`  📋 ${vec.name}`)
  const key = hex.decode(vec.key)
  const nonce = hex.decode(vec.nonce)
  const plaintext = concatBytes(...vec.blocks.map((b) => hex.decode(b.plaintext)))
  const ciphertext = concatBytes(...vec.blocks.map((b) => hex.decode(b.ciphertext)))

  const enc = new CTR(key, nonce).encrypt(plaintext)
  assertEqual(enc, ciphertext, `${vec.name} encrypt`)

  const dec = new CTR(key, nonce).decrypt(ciphertext)
  assertEqual(dec, plaintext, `${vec.name} decrypt`)

  console.log("    ✓ encrypt/decrypt OK")
}

// ─── Datos parciales ─────────────────────────────────────────────────────────

console.log("\n── Datos parciales ──\n")

{
  const key = new Uint8Array(16).fill(0xaa)
  const nonce = new Uint8Array(16).fill(0xbb)

  for (const size of [1, 7, 13, 15, 16, 17, 31, 32, 33, 100, 255]) {
    const data = new Uint8Array(size)
    for (let i = 0; i < size; i++) data[i] = i & 0xff

    const enc = new CTR(key, nonce).encrypt(data)
    const dec = new CTR(key, nonce).decrypt(enc)
    assertEqual(dec, data, `roundtrip ${size} bytes`)
  }
  console.log("  ✓ Roundtrip para múltiples tamaños")
}

// ─── Validación cruzada Node.js crypto ───────────────────────────────────────

console.log("\n── Validación Cruzada: Node.js crypto ──\n")

for (const keyLen of [16, 24, 32]) {
  const key = new Uint8Array(keyLen)
  for (let i = 0; i < keyLen; i++) key[i] = i
  const nonce = new Uint8Array(16).fill(0x44)
  const alg = `aes-${keyLen * 8}-ctr` as string

  const sizes = [1, 7, 15, 16, 17, 31, 32, 48, 100, 255, 1024]

  for (const size of sizes) {
    const data = new Uint8Array(size)
    for (let i = 0; i < size; i++) data[i] = i & 0xff

    // Nuestra lib encrypt
    const ourEnc = new CTR(key, nonce).encrypt(data)

    // Node decrypt
    const nodeDecipher = createDecipheriv(alg, key, nonce)
    nodeDecipher.setAutoPadding(false)
    const nodeDec = Uint8Array.from(Buffer.concat([nodeDecipher.update(ourEnc), nodeDecipher.final()]))
    assertEqual(nodeDec, data, `AES-${keyLen * 8}/${size}b: our enc → node dec`)

    // Node encrypt
    const nodeCipher = createCipheriv(alg, key, nonce)
    nodeCipher.setAutoPadding(false)
    const nodeEnc = Uint8Array.from(Buffer.concat([nodeCipher.update(data), nodeCipher.final()]))

    // Nuestra lib decrypt
    const ourDec = new CTR(key, nonce).decrypt(nodeEnc)
    assertEqual(ourDec, data, `AES-${keyLen * 8}/${size}b: node enc → our dec`)

    // Ciphertexts idénticos
    assertEqual(ourEnc, nodeEnc, `AES-${keyLen * 8}/${size}b: ciphertext idéntico`)
  }
  console.log(`  ✓ AES-${keyLen * 8}-CTR: ${sizes.length} tamaños verificados`)
}

// ─── Validaciones de error ───────────────────────────────────────────────────

console.log("\n── Validación de errores ──\n")

assertThrows(() => new CTR(new Uint8Array(16), new Uint8Array(15)), "nonce de 15 bytes")
console.log("  ✓ Rechaza nonce de longitud inválida")

assertThrows(() => {
  const c = new CTR(new Uint8Array(16), new Uint8Array(16))
  c.encrypt(new Uint8Array(16))
  c.encrypt(new Uint8Array(16))
}, "doble encrypt")
console.log("  ✓ Previene doble encrypt")

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
