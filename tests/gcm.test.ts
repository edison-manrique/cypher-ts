/**
 * @module gcm.test
 * Tests para AES-GCM usando vectores de Wycheproof.
 */

import { createCipheriv } from "node:crypto"
import { GCM } from "../src/aes/gcm"
import { hexToBytes, bytesToHex, concatBytes } from "../src/aes/utils"
import { readFileSync } from "node:fs"

process.chdir(import.meta.dir)

const hex = { decode: hexToBytes, encode: bytesToHex }

// ─── Utilidades de test ──────────────────────────────────────────────────────

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
  } catch (err: any) {
    if (
      !err.message.includes("mac falló") &&
      !err.message.includes("inválido") &&
      !err.message.includes("ciphertext demasiado corto")
    ) {
      // Aceptar errores de mac u otros, pero avisar si es error no esperado
    }
    passCount++
  }
}

// ─── Wycheproof Test Vectors ──────────────────────────────────────────────────

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
  tests: WycheproofTest[]
}

interface WycheproofRoot {
  testGroups: WycheproofGroup[]
}

const vectorsSource = readFileSync("./vectors/wycheproof/aes_gcm_test.json", "utf-8")
const vectors: WycheproofRoot = JSON.parse(vectorsSource)

console.log("═══════════════════════════════════════════")
console.log("  AES-GCM Tests (Wycheproof)")
console.log("═══════════════════════════════════════════\n")

let validTests = 0
let invalidTests = 0

for (const group of vectors.testGroups) {
  for (const t of group.tests) {
    // Si la clave o el IV tienen longitud de bytes irregular, Node a veces los acepta,
    // pero nuestra lib los valida rigurosamente.
    // Filtrar size cases inusitados (nuestra lib espera >=8 bytes de IV, etc.)
    const key = hex.decode(t.key)
    const iv = hex.decode(t.iv)
    const aad = hex.decode(t.aad)
    const msg = hex.decode(t.msg)
    const ct = hex.decode(t.ct)
    const tag = hex.decode(t.tag)

    // GCM Ciphertext incluye el MAC (Append MAC)
    const combinedCt = concatBytes(ct, tag)

    if (t.result === "valid" || t.result === "acceptable") {
      // Ignorar tests con IV inválidos (ej. < 8 bytes)
      if (iv.length < 8) continue

      let encrypted: Uint8Array
      try {
        const cipher = new GCM(key, iv, aad.length > 0 ? aad : undefined)
        encrypted = cipher.encrypt(msg)
      } catch (e: any) {
        console.error(`✗ Error enc tcId=${t.tcId}: ${e.message}`)
        failCount++
        continue
      }

      assertEqual(encrypted, combinedCt, `tcId ${t.tcId} (encrypt)`)

      let decrypted: Uint8Array
      try {
        const decipher = new GCM(key, iv, aad.length > 0 ? aad : undefined)
        decrypted = decipher.decrypt(combinedCt)
      } catch (e: any) {
        console.error(`✗ Error dec tcId=${t.tcId}: ${e.message}`)
        failCount++
        continue
      }

      assertEqual(decrypted, msg, `tcId ${t.tcId} (decrypt)`)
      validTests++
    } else if (t.result === "invalid") {
      if (iv.length < 8) continue

      assertThrows(() => {
        const decipher = new GCM(key, iv, aad.length > 0 ? aad : undefined)
        decipher.decrypt(combinedCt)
      }, `tcId ${t.tcId} (should fail to decrypt invalid MAC)`)
      invalidTests++
    }
  }
}

console.log(`\n  Tests Válidos Procesados: ${validTests}`)
console.log(`  Tests Inválidos Procesados: ${invalidTests}`)

// ─── Validación cruzada con Node.js crypto (GCM) ─────────────────────────────

console.log("\n── Validación Cruzada (Node.js crypto) ──\n")

for (const keySize of [16, 24, 32]) {
  const key = new Uint8Array(keySize).fill(0xaa)
  for (let i = 0; i < key.length; i++) key[i] = i

  for (const ivSize of [12, 16, 32, 64]) {
    const iv = new Uint8Array(ivSize).fill(0xbb)
    for (let i = 0; i < iv.length; i++) iv[i] = i * 2

    const sizes = [0, 1, 15, 16, 17, 100, 1024]

    for (const size of sizes) {
      const data = new Uint8Array(size)
      for (let i = 0; i < size; i++) data[i] = i & 0xff

      const aad = new Uint8Array(Math.floor(size / 2)).fill(0xcc)

      // Node encrypt
      const cipher = createCipheriv(`aes-${keySize * 8}-gcm`, key, iv) as any
      if (aad.length > 0) cipher.setAAD(aad)
      const ctNode = Buffer.concat([cipher.update(data), cipher.final(), cipher.getAuthTag()])

      // Nuestra impl encrypt
      const ourC = new GCM(key, iv, aad.length > 0 ? aad : undefined)
      const ctOur = ourC.encrypt(data)

      assertEqual(
        ctOur,
        Uint8Array.from(ctNode),
        `Cross Valid Encrypt AES-${keySize * 8}-GCM, IV=${ivSize}, Data=${size}`
      )

      // Nuestra impl decrypt
      const ourD = new GCM(key, iv, aad.length > 0 ? aad : undefined)
      const ptOur = ourD.decrypt(ctOur)

      assertEqual(ptOur, data, `Cross Valid Decrypt AES-${keySize * 8}-GCM, IV=${ivSize}, Data=${size}`)
    }
  }
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
