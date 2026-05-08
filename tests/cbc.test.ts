/**
 * @module cbc.test
 * Tests para AES-CBC usando vectores oficiales NIST SP 800-38A
 * y validación cruzada con Node.js crypto.
 *
 * Vectores: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
 * Sección F.2: CBC-AES128, CBC-AES192, CBC-AES256
 */

import { createCipheriv, createDecipheriv } from "node:crypto"
import { CBC, hexToBytes, bytesToHex, concatBytes } from "../src/aes/index"

process.chdir(import.meta.dir)

// ─── Utilidades de test ──────────────────────────────────────────────────────

const hex = {
  decode: hexToBytes,
  encode: bytesToHex
}

let testCount = 0
let passCount = 0
let failCount = 0

function assert(condition: boolean, message: string): void {
  testCount++
  if (condition) {
    passCount++
  } else {
    failCount++
    console.error(`  ✗ FAIL: ${message}`)
  }
}

function assertEqual(a: Uint8Array, b: Uint8Array, message: string): void {
  const aHex = hex.encode(a)
  const bHex = hex.encode(b)
  testCount++
  if (aHex === bHex) {
    passCount++
  } else {
    failCount++
    console.error(`  ✗ FAIL: ${message}`)
    console.error(`    esperado: ${bHex}`)
    console.error(`    obtenido: ${aHex}`)
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

// ─── Vectores NIST SP 800-38A (Sección F.2) ─────────────────────────────────

interface NistBlock {
  plaintext: string
  ciphertext: string
}

interface NistVector {
  name: string
  key: string
  iv: string
  blocks: NistBlock[]
}

const NIST_CBC_VECTORS: NistVector[] = [
  // F.2.1 CBC-AES128.Encrypt
  {
    name: "CBC-AES128",
    key: "2b7e151628aed2a6abf7158809cf4f3c",
    iv: "000102030405060708090a0b0c0d0e0f",
    blocks: [
      { plaintext: "6bc1bee22e409f96e93d7e117393172a", ciphertext: "7649abac8119b246cee98e9b12e9197d" },
      { plaintext: "ae2d8a571e03ac9c9eb76fac45af8e51", ciphertext: "5086cb9b507219ee95db113a917678b2" },
      { plaintext: "30c81c46a35ce411e5fbc1191a0a52ef", ciphertext: "73bed6b8e3c1743b7116e69e22229516" },
      { plaintext: "f69f2445df4f9b17ad2b417be66c3710", ciphertext: "3ff1caa1681fac09120eca307586e1a7" }
    ]
  },
  // F.2.3 CBC-AES192.Encrypt
  {
    name: "CBC-AES192",
    key: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
    iv: "000102030405060708090a0b0c0d0e0f",
    blocks: [
      { plaintext: "6bc1bee22e409f96e93d7e117393172a", ciphertext: "4f021db243bc633d7178183a9fa071e8" },
      { plaintext: "ae2d8a571e03ac9c9eb76fac45af8e51", ciphertext: "b4d9ada9ad7dedf4e5e738763f69145a" },
      { plaintext: "30c81c46a35ce411e5fbc1191a0a52ef", ciphertext: "571b242012fb7ae07fa9baac3df102e0" },
      { plaintext: "f69f2445df4f9b17ad2b417be66c3710", ciphertext: "08b0e27988598881d920a9e64f5615cd" }
    ]
  },
  // F.2.5 CBC-AES256.Encrypt
  {
    name: "CBC-AES256",
    key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
    iv: "000102030405060708090a0b0c0d0e0f",
    blocks: [
      { plaintext: "6bc1bee22e409f96e93d7e117393172a", ciphertext: "f58c4c04d6e5f1ba779eabfb5f7bfbd6" },
      { plaintext: "ae2d8a571e03ac9c9eb76fac45af8e51", ciphertext: "9cfc4e967edb808d679f777bc6702c7d" },
      { plaintext: "30c81c46a35ce411e5fbc1191a0a52ef", ciphertext: "39f23369a9d9bacfa530e26304231461" },
      { plaintext: "f69f2445df4f9b17ad2b417be66c3710", ciphertext: "b2eb05e2c39be9fcda6c19078c6a9d1b" }
    ]
  }
]

// ─── Tests NIST ──────────────────────────────────────────────────────────────

console.log("═══════════════════════════════════════════")
console.log("  AES-CBC Tests")
console.log("═══════════════════════════════════════════\n")

console.log("── NIST SP 800-38A Vectores Oficiales ──\n")

for (const vec of NIST_CBC_VECTORS) {
  console.log(`  📋 ${vec.name}`)

  const key = hex.decode(vec.key)
  const iv = hex.decode(vec.iv)
  const plaintext = concatBytes(...vec.blocks.map((b) => hex.decode(b.plaintext)))
  const ciphertext = concatBytes(...vec.blocks.map((b) => hex.decode(b.ciphertext)))

  // Test encrypt (sin padding ya que los datos son múltiplo de 16)
  const cipher = new CBC(key, iv, { disablePadding: true })
  const encrypted = cipher.encrypt(plaintext)
  assertEqual(encrypted, ciphertext, `${vec.name} encrypt`)

  // Test decrypt (nueva instancia por single-use)
  const cipher2 = new CBC(key, iv, { disablePadding: true })
  const decrypted = cipher2.decrypt(ciphertext)
  assertEqual(decrypted, plaintext, `${vec.name} decrypt`)

  console.log(`    ✓ encrypt/decrypt OK`)
}

// ─── Tests con PKCS#7 Padding ────────────────────────────────────────────────

console.log("\n── PKCS#7 Padding ──\n")

{
  const key = new Uint8Array(16).fill(0xaa)
  const iv = new Uint8Array(16).fill(0xbb)

  // Test: bloque exacto (debería agregar bloque completo de padding)
  const exact = new Uint8Array(16).fill(0x42)
  const c1 = new CBC(key, iv)
  const enc1 = c1.encrypt(exact)
  assert(enc1.length === 32, "padding: bloque exacto produce 2 bloques")
  const c1d = new CBC(key, iv)
  const dec1 = c1d.decrypt(enc1)
  assertEqual(dec1, exact, "padding: roundtrip bloque exacto")
  console.log("  ✓ Bloque exacto (16 bytes → 32 bytes)")

  // Test: datos parciales (13 bytes → 16 bytes con 3 de padding)
  const partial = new Uint8Array(13).fill(0x55)
  const c2 = new CBC(key, iv)
  const enc2 = c2.encrypt(partial)
  assert(enc2.length === 16, "padding: 13 bytes produce 1 bloque")
  const c2d = new CBC(key, iv)
  const dec2 = c2d.decrypt(enc2)
  assertEqual(dec2, partial, "padding: roundtrip 13 bytes")
  console.log("  ✓ Datos parciales (13 bytes → 16 bytes)")

  // Test: datos multi-bloque parciales (35 bytes → 48 bytes)
  const multi = new Uint8Array(35).fill(0x77)
  const c3 = new CBC(key, iv)
  const enc3 = c3.encrypt(multi)
  assert(enc3.length === 48, "padding: 35 bytes produce 3 bloques")
  const c3d = new CBC(key, iv)
  const dec3 = c3d.decrypt(enc3)
  assertEqual(dec3, multi, "padding: roundtrip 35 bytes")
  console.log("  ✓ Multi-bloque parcial (35 bytes → 48 bytes)")

  // Test: un solo byte
  const one = new Uint8Array([0xfe])
  const c4 = new CBC(key, iv)
  const enc4 = c4.encrypt(one)
  assert(enc4.length === 16, "padding: 1 byte produce 1 bloque")
  const c4d = new CBC(key, iv)
  const dec4 = c4d.decrypt(enc4)
  assertEqual(dec4, one, "padding: roundtrip 1 byte")
  console.log("  ✓ Un solo byte (1 byte → 16 bytes)")

  // Test: datos vacíos
  const empty = new Uint8Array(0)
  const c5 = new CBC(key, iv)
  const enc5 = c5.encrypt(empty)
  assert(enc5.length === 16, "padding: vacío produce 1 bloque de padding")
  const c5d = new CBC(key, iv)
  const dec5 = c5d.decrypt(enc5)
  assertEqual(dec5, empty, "padding: roundtrip vacío")
  console.log("  ✓ Datos vacíos (0 bytes → 16 bytes)")
}

// ─── Validación cruzada con Node.js crypto ───────────────────────────────────

console.log("\n── Validación cruzada: Node.js crypto ──\n")

function nodeEncrypt(alg: string, key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array {
  const cipher = createCipheriv(alg, key, iv)
  return Uint8Array.from(Buffer.concat([cipher.update(data), cipher.final()]))
}

function nodeDecrypt(alg: string, key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array {
  const decipher = createDecipheriv(alg, key, iv)
  return Uint8Array.from(Buffer.concat([decipher.update(data), decipher.final()]))
}

const crossTests = [
  { name: "AES-128-CBC", keyLen: 16, alg: "aes-128-cbc" },
  { name: "AES-192-CBC", keyLen: 24, alg: "aes-192-cbc" },
  { name: "AES-256-CBC", keyLen: 32, alg: "aes-256-cbc" }
]

for (const t of crossTests) {
  const key = new Uint8Array(t.keyLen).fill(0x33)
  const iv = new Uint8Array(16).fill(0x44)

  // Datos de distintos tamaños
  const sizes = [1, 7, 15, 16, 17, 31, 32, 48, 100, 255, 1024]

  for (const size of sizes) {
    const data = new Uint8Array(size)
    for (let i = 0; i < size; i++) data[i] = i & 0xff

    // Cifrar con nuestra lib, descifrar con Node
    const ourEnc = new CBC(key, iv).encrypt(data)
    const nodeDec = nodeDecrypt(t.alg, key, iv, ourEnc)
    assertEqual(nodeDec, data, `${t.name}/${size}b: our encrypt → node decrypt`)

    // Cifrar con Node, descifrar con nuestra lib
    const nodeEnc = nodeEncrypt(t.alg, key, iv, data)
    const ourDec = new CBC(key, iv).decrypt(nodeEnc)
    assertEqual(ourDec, data, `${t.name}/${size}b: node encrypt → our decrypt`)

    // Verificar que ambos producen el mismo ciphertext
    assertEqual(ourEnc, nodeEnc, `${t.name}/${size}b: ciphertext idéntico`)
  }
  console.log(`  ✓ ${t.name}: ${sizes.length} tamaños verificados`)
}

// ─── Tests de errores ────────────────────────────────────────────────────────

console.log("\n── Validación de errores ──\n")

// Clave inválida (la validación ocurre al cifrar, durante key expansion)
assertThrows(
  () => new CBC(new Uint8Array(15), new Uint8Array(16)).encrypt(new Uint8Array(16)),
  "debería rechazar clave de 15 bytes"
)
console.log("  ✓ Rechaza clave de longitud inválida")

// IV inválido
assertThrows(() => new CBC(new Uint8Array(16), new Uint8Array(15)), "debería rechazar IV de 15 bytes")
console.log("  ✓ Rechaza IV de longitud inválida")

// Ciphertext no múltiplo de 16 (sin padding)
assertThrows(
  () => new CBC(new Uint8Array(16), new Uint8Array(16)).decrypt(new Uint8Array(17)),
  "debería rechazar ciphertext no alineado"
)
console.log("  ✓ Rechaza ciphertext no múltiplo de 16")

// No se puede cifrar dos veces con misma instancia
assertThrows(() => {
  const c = new CBC(new Uint8Array(16), new Uint8Array(16))
  c.encrypt(new Uint8Array(16))
  c.encrypt(new Uint8Array(16))
}, "debería prevenir doble encrypt")
console.log("  ✓ Previene doble encrypt con misma instancia")

// disablePadding con datos no alineados
assertThrows(
  () => new CBC(new Uint8Array(16), new Uint8Array(16), { disablePadding: true }).encrypt(new Uint8Array(15)),
  "debería rechazar datos no alineados sin padding"
)
console.log("  ✓ Rechaza datos no alineados con padding deshabilitado")

// ─── Tests con claves de distinta longitud ───────────────────────────────────

console.log("\n── Claves 128/192/256 bits ──\n")

for (const keyLen of [16, 24, 32]) {
  const key = new Uint8Array(keyLen)
  for (let i = 0; i < keyLen; i++) key[i] = i
  const iv = new Uint8Array(16).fill(0xff)
  const data = new Uint8Array(64)
  for (let i = 0; i < 64; i++) data[i] = i * 3

  const c = new CBC(key, iv, { disablePadding: true })
  const enc = c.encrypt(data)
  const c2 = new CBC(key, iv, { disablePadding: true })
  const dec = c2.decrypt(enc)
  assertEqual(dec, data, `AES-${keyLen * 8} roundtrip`)
  console.log(`  ✓ AES-${keyLen * 8}: roundtrip OK`)
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
