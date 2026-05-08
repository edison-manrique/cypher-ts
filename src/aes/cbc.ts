/**
 * @module cbc
 * AES-CBC (Cipher Block Chaining) mode.
 *
 * Cada bloque de plaintext se XOR con el bloque anterior de ciphertext antes de cifrarse.
 * Soporta padding PKCS#7 (habilitado por defecto) y datos sin padding.
 *
 * Referencia: NIST SP 800-38A, Sección 6.2
 */

import { BLOCK_SIZE } from "./constants"
import { encryptBlock, decryptBlock, expandKeyLE, expandKeyDecLE } from "./aes-core"
import {
  abytes,
  u32,
  clean,
  isAligned32,
  copyBytes,
  getOutput,
  complexOverlapBytes,
  type CipherWithOutput,
  type BlockOpts
} from "./utils"

// ─── PKCS#7 Padding ─────────────────────────────────────────────────────────

/** Valida y remueve padding PKCS#7. */
function validatePKCS7(data: Uint8Array, pkcs7: boolean): Uint8Array {
  if (!pkcs7) return data
  const len = data.length
  if (!len) throw new Error("aes/pkcs7: ciphertext vacío no permitido")
  const lastByte = data[len - 1]
  if (lastByte <= 0 || lastByte > 16) throw new Error("aes/pkcs7: padding inválido")
  const out = data.subarray(0, -lastByte)
  for (let i = 0; i < lastByte; i++) if (data[len - i - 1] !== lastByte) throw new Error("aes/pkcs7: padding inválido")
  return out
}

/** Aplica padding PKCS#7 al bloque final incompleto. */
function padPKCS7(left: Uint8Array): Uint32Array {
  const tmp = new Uint8Array(16)
  const tmp32 = u32(tmp)
  tmp.set(left)
  const paddingByte = BLOCK_SIZE - left.length
  for (let i = BLOCK_SIZE - paddingByte; i < BLOCK_SIZE; i++) tmp[i] = paddingByte
  return tmp32
}

// ─── Clase CBC ───────────────────────────────────────────────────────────────

/**
 * **AES-CBC** (Cipher Block Chaining Mode)
 *
 * Cada bloque de plaintext se XOR con el ciphertext anterior antes de cifrarse.
 * Requiere un IV de 16 bytes y padding adecuado.
 * No autenticado: necesita MAC para integridad.
 *
 * @example
 * ```ts
 * const cipher = new CBC(key, iv)
 * const encrypted = cipher.encrypt(plaintext)
 *
 * const decipher = new CBC(key, iv)
 * const decrypted = decipher.decrypt(encrypted)
 * ```
 */
export class CBC implements CipherWithOutput {
  private key: Uint8Array
  private iv: Uint8Array
  private pkcs7: boolean
  private used = false

  /**
   * @param key Clave AES de 16/24/32 bytes
   * @param iv Vector de inicialización de 16 bytes
   * @param opts Opciones: `{ disablePadding: true }` para desactivar PKCS#7
   */
  constructor(key: Uint8Array, iv: Uint8Array, opts: BlockOpts = {}) {
    abytes(key)
    abytes(iv, BLOCK_SIZE, "iv")
    this.key = key
    this.iv = iv
    this.pkcs7 = !opts.disablePadding
  }

  /**
   * Cifra plaintext con AES-CBC.
   *
   * 1. XOR plaintext[i] con ciphertext[i-1] (o IV para i=0)
   * 2. Cifrar el resultado con AES
   * 3. El output se convierte en el "vector" para el siguiente bloque
   */
  encrypt(plaintext: Uint8Array, dst?: Uint8Array): Uint8Array {
    if (this.used) throw new Error("CBC: no se puede encrypt() dos veces con la misma instancia")
    this.used = true
    abytes(plaintext)

    const { pkcs7 } = this
    let outLen = plaintext.length
    const remaining = outLen % BLOCK_SIZE
    if (!pkcs7 && remaining !== 0) throw new Error("aes-cbc: plaintext sin padding con padding deshabilitado")

    if (!isAligned32(plaintext)) plaintext = copyBytes(plaintext)
    const b = u32(plaintext)

    if (pkcs7) {
      let left = BLOCK_SIZE - remaining
      if (!left) left = BLOCK_SIZE
      outLen = outLen + left
    }

    dst = getOutput(outLen, dst)
    complexOverlapBytes(plaintext, dst)
    const o = u32(dst)

    const xk = expandKeyLE(this.key)
    let _iv = this.iv
    const toClean: (Uint8Array | Uint32Array)[] = [xk]
    if (!isAligned32(_iv)) toClean.push((_iv = copyBytes(_iv)))
    const n32 = u32(_iv)

    let s0 = n32[0],
      s1 = n32[1],
      s2 = n32[2],
      s3 = n32[3]
    let i = 0

    // Bloques completos
    for (; i + 4 <= b.length; ) {
      s0 ^= b[i + 0]
      s1 ^= b[i + 1]
      s2 ^= b[i + 2]
      s3 ^= b[i + 3]
      ;({ s0, s1, s2, s3 } = encryptBlock(xk, s0, s1, s2, s3))
      o[i++] = s0
      o[i++] = s1
      o[i++] = s2
      o[i++] = s3
    }

    // Último bloque con padding PKCS#7
    if (pkcs7) {
      const tmp32 = padPKCS7(plaintext.subarray(i * 4))
      s0 ^= tmp32[0]
      s1 ^= tmp32[1]
      s2 ^= tmp32[2]
      s3 ^= tmp32[3]
      ;({ s0, s1, s2, s3 } = encryptBlock(xk, s0, s1, s2, s3))
      o[i++] = s0
      o[i++] = s1
      o[i++] = s2
      o[i++] = s3
    }

    clean(...toClean)
    return dst
  }

  /**
   * Descifra ciphertext con AES-CBC.
   *
   * 1. Descifrar ciphertext[i] con AES
   * 2. XOR resultado con ciphertext[i-1] (o IV para i=0)
   * 3. Guardar ciphertext[i] como vector para el siguiente bloque
   */
  decrypt(ciphertext: Uint8Array, dst?: Uint8Array): Uint8Array {
    abytes(ciphertext)
    if (ciphertext.length % BLOCK_SIZE !== 0)
      throw new Error("aes-cbc.decrypt: ciphertext debe ser múltiplo de " + BLOCK_SIZE + " bytes")

    const xk = expandKeyDecLE(this.key)
    let _iv = this.iv
    const toClean: (Uint8Array | Uint32Array)[] = [xk]
    if (!isAligned32(_iv)) toClean.push((_iv = copyBytes(_iv)))
    const n32 = u32(_iv)

    dst = getOutput(ciphertext.length, dst)
    if (!isAligned32(ciphertext)) toClean.push((ciphertext = copyBytes(ciphertext)))
    complexOverlapBytes(ciphertext, dst)
    const b = u32(ciphertext)
    const o = u32(dst)

    let s0 = n32[0],
      s1 = n32[1],
      s2 = n32[2],
      s3 = n32[3]

    for (let i = 0; i + 4 <= b.length; ) {
      const ps0 = s0,
        ps1 = s1,
        ps2 = s2,
        ps3 = s3
      s0 = b[i + 0]
      s1 = b[i + 1]
      s2 = b[i + 2]
      s3 = b[i + 3]
      const { s0: o0, s1: o1, s2: o2, s3: o3 } = decryptBlock(xk, s0, s1, s2, s3)
      o[i++] = o0 ^ ps0
      o[i++] = o1 ^ ps1
      o[i++] = o2 ^ ps2
      o[i++] = o3 ^ ps3
    }

    clean(...toClean)
    return validatePKCS7(dst, this.pkcs7)
  }

  /** Limpia claves de memoria. */
  destroy(): void {
    // no-op: keys are owned by caller
  }
}
