/**
 * @module ctr
 * AES-CTR (Counter Mode).
 *
 * Convierte un cifrador de bloques en un cifrador de flujo usando un contador.
 * Encrypt y Decrypt son la misma operación (XOR con keystream).
 * Counter de 128 bits con wrap-around completo.
 *
 * Referencia: NIST SP 800-38A, Sección 6.5
 */

import { BLOCK_SIZE, BLOCK_SIZE32 } from "./constants"
import { encryptBlock, expandKeyLE } from "./aes-core"
import {
  abytes,
  u8,
  u32,
  clean,
  isAligned32,
  copyBytes,
  getOutput,
  complexOverlapBytes,
  type CipherWithOutput
} from "./utils"

// ─── Incremento de contador ──────────────────────────────────────────────────

/**
 * Incrementa un Uint8Array como un entero big-endian de 128 bits.
 * Soporta wrap-around completo.
 */
function incBytes(data: Uint8Array, carry: number = 1): void {
  for (let i = data.length - 1; i >= 0 && carry > 0; i--) {
    carry = (carry + data[i]) | 0
    data[i] = carry & 0xff
    carry >>>= 8
  }
}

// ─── Clase CTR ───────────────────────────────────────────────────────────────

/**
 * **AES-CTR** (Counter Mode)
 *
 * Cifrador de flujo basado en AES. Cada bloque de plaintext se XOR
 * con el keystream generado al cifrar un contador incremental.
 *
 * - Encrypt y decrypt son la misma operación.
 * - Requiere un nonce/IV de 16 bytes.
 * - No autenticado: necesita MAC para integridad.
 * - Paralelizable por diseño.
 *
 * @example
 * ```ts
 * const cipher = new CTR(key, nonce)
 * const encrypted = cipher.encrypt(plaintext)
 * // Para descifrar:
 * const decipher = new CTR(key, nonce)
 * const decrypted = decipher.decrypt(encrypted)
 * ```
 */
export class CTR implements CipherWithOutput {
  private xk: Uint32Array
  private nonce: Uint8Array
  private used = false

  /**
   * @param key Clave AES de 16/24/32 bytes
   * @param nonce IV/Nonce de 16 bytes (counter inicial)
   */
  constructor(key: Uint8Array, nonce: Uint8Array) {
    abytes(key)
    abytes(nonce, BLOCK_SIZE, "nonce")
    this.xk = expandKeyLE(key)
    this.nonce = copyBytes(nonce) // copia para no mutar el original
  }

  /**
   * Procesa datos (encrypt/decrypt son idénticos en CTR).
   * Genera keystream cifrando el contador y XOR con los datos.
   */
  private process(src: Uint8Array, dst?: Uint8Array): Uint8Array {
    abytes(src)
    dst = getOutput(src.length, dst)
    const toClean: Uint8Array[] = []
    if (!isAligned32(src)) toClean.push((src = copyBytes(src)))
    complexOverlapBytes(src, dst)

    const ctr = this.nonce
    const c32 = u32(ctr)
    const src32 = u32(src)
    const dst32 = u32(dst)
    const srcLen = src.length
    const xk = this.xk

    // Generar primer bloque de keystream
    let { s0, s1, s2, s3 } = encryptBlock(xk, c32[0], c32[1], c32[2], c32[3])

    // Procesar bloques completos
    for (let i = 0; i + 4 <= src32.length; i += 4) {
      dst32[i + 0] = src32[i + 0] ^ s0
      dst32[i + 1] = src32[i + 1] ^ s1
      dst32[i + 2] = src32[i + 2] ^ s2
      dst32[i + 3] = src32[i + 3] ^ s3
      incBytes(ctr, 1) // Incrementar counter completo (128 bits)
      ;({ s0, s1, s2, s3 } = encryptBlock(xk, c32[0], c32[1], c32[2], c32[3]))
    }

    // Bytes restantes (< 16)
    const start = BLOCK_SIZE * Math.floor(src32.length / BLOCK_SIZE32)
    if (start < srcLen) {
      const b32 = new Uint32Array([s0, s1, s2, s3])
      const buf = u8(b32)
      for (let i = start, pos = 0; i < srcLen; i++, pos++) dst[i] = src[i] ^ buf[pos]
      clean(b32)
    }

    if (toClean.length) clean(...toClean)
    return dst
  }

  /** Cifra plaintext con AES-CTR. */
  encrypt(plaintext: Uint8Array, dst?: Uint8Array): Uint8Array {
    if (this.used) throw new Error("CTR: no se puede encrypt() dos veces con la misma instancia")
    this.used = true
    return this.process(plaintext, dst)
  }

  /** Descifra ciphertext con AES-CTR (idéntico a encrypt). */
  decrypt(ciphertext: Uint8Array, dst?: Uint8Array): Uint8Array {
    return this.process(ciphertext, dst)
  }

  /** Limpia claves de memoria. */
  destroy(): void {
    clean(this.xk, this.nonce)
  }
}
