/**
 * @module gcm
 * AES-GCM (Galois/Counter Mode).
 *
 * Combina modo CTR con GHASH para proveer Autenticación y Cifrado Simétricos (AEAD).
 * Soporta datos autenticados adicionales (AAD).
 *
 * Referencia: NIST SP 800-38D
 * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
 */

import { BLOCK_SIZE, BLOCK_SIZE32 } from "./constants"
import { encryptBlock, expandKeyLE } from "./aes-core"
import { GHASH } from "./ghash"
import {
  abytes,
  u8,
  u32,
  clean,
  isAligned32,
  copyBytes,
  getOutput,
  equalBytes,
  createView,
  u64Lengths,
  type Cipher
} from "./utils"

const EMPTY_BLOCK = new Uint8Array(BLOCK_SIZE)

// ─── CTR32 Interno para GCM ──────────────────────────────────────────────────

/**
 * Función interna AES-CTR con counter u32 big-endian (específica para GCM).
 * El counter ocupa los últimos 4 bytes del nonce de 16 bytes.
 */
function ctr32(xk: Uint32Array, nonce: Uint8Array, src: Uint8Array, dst?: Uint8Array): Uint8Array {
  abytes(nonce, BLOCK_SIZE, "nonce")
  abytes(src)
  dst = getOutput(src.length, dst)
  const ctr = nonce
  const c32 = u32(ctr)
  const view = createView(ctr)
  const src32 = u32(src)
  const dst32 = u32(dst)
  const ctrPos = 12
  const isLE = false
  const srcLen = src.length

  let ctrNum = view.getUint32(ctrPos, isLE)
  let { s0, s1, s2, s3 } = encryptBlock(xk, c32[0], c32[1], c32[2], c32[3])

  for (let i = 0; i + 4 <= src32.length; i += 4) {
    dst32[i + 0] = src32[i + 0] ^ s0
    dst32[i + 1] = src32[i + 1] ^ s1
    dst32[i + 2] = src32[i + 2] ^ s2
    dst32[i + 3] = src32[i + 3] ^ s3
    ctrNum = (ctrNum + 1) >>> 0
    view.setUint32(ctrPos, ctrNum, isLE)
    ;({ s0, s1, s2, s3 } = encryptBlock(xk, c32[0], c32[1], c32[2], c32[3]))
  }

  const start = BLOCK_SIZE * Math.floor(src32.length / BLOCK_SIZE32)
  if (start < srcLen) {
    const b32 = new Uint32Array([s0, s1, s2, s3])
    const buf = u8(b32)
    for (let i = start, pos = 0; i < srcLen; i++, pos++) dst[i] = src[i] ^ buf[pos]
    clean(b32)
  }
  return dst
}

// ─── Utilidades internas ─────────────────────────────────────────────────────

/** Calcula el tag GHASH + tagMask. */
function computeTag(key: Uint8Array, data: Uint8Array, AAD?: Uint8Array): Uint8Array {
  const aadLength = AAD ? AAD.length : 0
  const hash = new GHASH(key, data.length + aadLength)
  if (AAD) hash.update(AAD)
  hash.update(data)
  const num = u64Lengths(8 * data.length, 8 * aadLength, false)
  hash.update(num)
  const res = hash.digest()
  clean(num)
  return res
}

// ─── Clase GCM ───────────────────────────────────────────────────────────────

/**
 * **AES-GCM** (Galois/Counter Mode)
 *
 * AEAD que combina CTR para cifrado y GHASH para autenticación.
 * Produce un ciphertext con un tag MAC de 16 bytes al final.
 *
 * - Nonce recomendado: 12 bytes (mínimo 8 bytes).
 * - Soporta AAD (datos autenticados adicionales).
 * - Tag de 128 bits integrado en el output.
 *
 * @example
 * ```ts
 * const cipher = new GCM(key, nonce, aad)
 * const encrypted = cipher.encrypt(plaintext) // ciphertext || tag
 *
 * const decipher = new GCM(key, nonce, aad)
 * const decrypted = decipher.decrypt(encrypted) // valida tag y descifra
 * ```
 */
export class GCM implements Cipher {
  private key: Uint8Array
  private nonce: Uint8Array
  private AAD?: Uint8Array
  private tagLength = 16

  /**
   * @param key Clave AES de 16/24/32 bytes
   * @param nonce IV único. Estándar: 12 bytes. Mínimo: 8 bytes.
   * @param AAD Datos autenticados adicionales (opcional)
   */
  constructor(key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array) {
    abytes(key)
    abytes(nonce)
    if (nonce.length < 8) throw new Error("aes-gcm: longitud de nonce inválida (mín. 8 bytes)")
    this.key = key
    this.nonce = nonce
    this.AAD = AAD
  }

  /** Aplica el mask final del tag. */
  private _computeTag(authKey: Uint8Array, tagMask: Uint8Array, data: Uint8Array): Uint8Array {
    const tag = computeTag(authKey, data, this.AAD)
    for (let i = 0; i < tagMask.length; i++) tag[i] ^= tagMask[i]
    return tag
  }

  /** Deriva subclaves (H), contador inicial (J0), y tagMask. */
  private deriveKeys(): {
    xk: Uint32Array
    authKey: Uint8Array
    counter: Uint8Array
    tagMask: Uint8Array
  } {
    const xk = expandKeyLE(this.key)
    const authKey = EMPTY_BLOCK.slice()
    const counter = EMPTY_BLOCK.slice()

    // H = E(K, 0^128)
    ctr32(xk, counter, counter, authKey)

    // NIST 800-38d: IVs de 96 bits vs distinto de 96 bits
    if (this.nonce.length === 12) {
      counter.set(this.nonce)
      counter[15] = 1
    } else {
      const nonceLen = EMPTY_BLOCK.slice()
      const view = createView(nonceLen)
      view.setBigUint64(8, BigInt(this.nonce.length * 8), false)
      const g = new GHASH(authKey, this.nonce.length + 16)
      g.update(this.nonce).update(nonceLen)
      g.digestInto(counter)
      g.destroy()
    }

    // tagMask = E(K, J0)
    const tagMask = ctr32(xk, counter, EMPTY_BLOCK)
    return { xk, authKey, counter, tagMask }
  }

  /** Cifra plaintext → ciphertext || tag (16 bytes). */
  encrypt(plaintext: Uint8Array): Uint8Array {
    const { xk, authKey, counter, tagMask } = this.deriveKeys()
    const out = new Uint8Array(plaintext.length + this.tagLength)
    const toClean: (Uint8Array | Uint32Array)[] = [xk, authKey, counter, tagMask]

    if (!isAligned32(plaintext)) toClean.push((plaintext = copyBytes(plaintext)))

    ctr32(xk, counter, plaintext, out.subarray(0, plaintext.length))

    const tag = this._computeTag(authKey, tagMask, out.subarray(0, out.length - this.tagLength))
    toClean.push(tag)
    out.set(tag, plaintext.length)

    clean(...toClean)
    return out
  }

  /** Descifra ciphertext || tag → plaintext. Lanza error si el tag es inválido. */
  decrypt(ciphertext: Uint8Array): Uint8Array {
    if (ciphertext.length < this.tagLength)
      throw new Error(`aes-gcm: ciphertext demasiado corto (mínimo tag=${this.tagLength})`)

    const { xk, authKey, counter, tagMask } = this.deriveKeys()
    const toClean: (Uint8Array | Uint32Array)[] = [xk, authKey, tagMask, counter]

    if (!isAligned32(ciphertext)) toClean.push((ciphertext = copyBytes(ciphertext)))

    const data = ciphertext.subarray(0, -this.tagLength)
    const passedTag = ciphertext.subarray(-this.tagLength)

    const tag = this._computeTag(authKey, tagMask, data)
    toClean.push(tag)

    if (!equalBytes(tag, passedTag)) {
      clean(...toClean)
      throw new Error("aes-gcm: mac falló (tag ghash inválido)")
    }

    const out = ctr32(xk, counter, data)
    clean(...toClean)
    return out
  }

  /** Limpia datos sensibles. */
  destroy(): void {
    // no-op: keys are owned by caller
  }
}
