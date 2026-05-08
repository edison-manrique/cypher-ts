/**
 * @module cmac
 * AES-CMAC (Cipher-based Message Authentication Code).
 *
 * Genera un MAC de 128 bits usando AES como primitiva.
 * Implementación según RFC 4493.
 *
 * Referencia: https://www.rfc-editor.org/rfc/rfc4493.html
 */

import { BLOCK_SIZE } from "./constants"
import { expandKeyLE, encryptBlockInPlace, validateKeyLength } from "./aes-core"
import { abytes, clean } from "./utils"

// ─── Utilidades internas ─────────────────────────────────────────────────────

/**
 * Duplica un bloque en GF(2^128) (left shift + XOR condicional con 0x87).
 * RFC 4493 Sección 2.3: dbl(L)
 */
function dbl(block: Uint8Array): Uint8Array {
  let carry = 0
  for (let i = BLOCK_SIZE - 1; i >= 0; i--) {
    const newCarry = (block[i] & 0x80) >>> 7
    block[i] = (block[i] << 1) | carry
    carry = newCarry
  }
  if (carry) block[BLOCK_SIZE - 1] ^= 0x87
  return block
}

/**
 * XOR in-place: a ^= b (misma longitud).
 */
function xorBlock(a: Uint8Array, b: Uint8Array): Uint8Array {
  for (let i = 0; i < a.length; i++) a[i] ^= b[i]
  return a
}

// ─── Clase CMAC ──────────────────────────────────────────────────────────────

/**
 * **AES-CMAC** (Cipher-based Message Authentication Code)
 *
 * Genera un MAC de 128 bits (16 bytes) usando AES.
 * Soporta mensajes de longitud arbitraria.
 *
 * @example
 * ```ts
 * // Uso directo:
 * const tag = CMAC.digest(key, message)
 *
 * // Uso incremental:
 * const mac = new CMAC(key)
 * mac.update(data1)
 * mac.update(data2)
 * const tag = mac.digest()
 * ```
 */
export class CMAC {
  private xk: Uint32Array
  private k1: Uint8Array
  private k2: Uint8Array
  private buffer: Uint8Array
  private destroyed: boolean

  /**
   * @param key Clave AES de 16/24/32 bytes
   */
  constructor(key: Uint8Array) {
    abytes(key)
    validateKeyLength(key)
    this.xk = expandKeyLE(key)
    this.buffer = new Uint8Array(0)
    this.destroyed = false

    // L = AES_K(0^128)
    const L = new Uint8Array(BLOCK_SIZE)
    encryptBlockInPlace(this.xk, L)

    // K1 = dbl(L), K2 = dbl(K1) — RFC 4493 §2.3
    this.k1 = dbl(L)
    this.k2 = dbl(new Uint8Array(this.k1))
  }

  /**
   * Alimenta datos al CMAC.
   * Se pueden hacer múltiples llamadas a update().
   */
  update(data: Uint8Array): CMAC {
    if (this.destroyed) throw new Error("CMAC: instancia destruida")
    abytes(data)
    const newBuffer = new Uint8Array(this.buffer.length + data.length)
    newBuffer.set(this.buffer)
    newBuffer.set(data, this.buffer.length)
    this.buffer = newBuffer
    return this
  }

  /**
   * Calcula y retorna el MAC de 128 bits.
   * RFC 4493 §2.4: MAC Generation
   */
  digest(): Uint8Array {
    if (this.destroyed) throw new Error("CMAC: instancia destruida")
    const { buffer, xk, k1, k2 } = this
    const msgLen = buffer.length

    // Paso 2: n = ceil(len/blockSize)
    let n = Math.ceil(msgLen / BLOCK_SIZE)

    // Paso 3: flag = true si el último bloque es completo
    let flag: boolean
    if (n === 0) {
      n = 1
      flag = false
    } else {
      flag = msgLen % BLOCK_SIZE === 0
    }

    // Paso 4: M_last
    const lastBlockStart = (n - 1) * BLOCK_SIZE
    const lastBlockData = buffer.subarray(lastBlockStart)
    let mLast: Uint8Array

    if (flag) {
      // M_last = M_n XOR K1
      mLast = xorBlock(new Uint8Array(lastBlockData), k1)
    } else {
      // M_last = pad(M_n) XOR K2 — padding 10*
      const padded = new Uint8Array(BLOCK_SIZE)
      padded.set(lastBlockData)
      padded[lastBlockData.length] = 0x80
      mLast = xorBlock(padded, k2)
    }

    // Paso 5: X = 0^128
    const x = new Uint8Array(BLOCK_SIZE)

    // Paso 6: CBC-MAC de bloques anteriores
    for (let i = 0; i < n - 1; i++) {
      const mi = buffer.subarray(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE)
      xorBlock(x, mi) // Y = X XOR M_i
      encryptBlockInPlace(xk, x) // X = AES(K, Y)
    }

    // Paso 7: último bloque
    xorBlock(x, mLast) // Y = M_last XOR X
    encryptBlockInPlace(xk, x) // T = AES(K, Y)

    clean(mLast)
    return x // T (tag de 128 bits)
  }

  /** Destruye datos sensibles. */
  destroy(): void {
    if (this.destroyed) return
    this.destroyed = true
    clean(this.buffer, this.xk, this.k1, this.k2)
  }

  // ─── API estática ────────────────────────────────────────────────────────

  /**
   * Calcula CMAC en una sola llamada.
   * @param key Clave AES
   * @param message Mensaje a autenticar
   * @returns Tag de 128 bits (16 bytes)
   */
  static digest(key: Uint8Array, message: Uint8Array): Uint8Array {
    const mac = new CMAC(key)
    mac.update(message)
    const tag = mac.digest()
    mac.destroy()
    return tag
  }
}
