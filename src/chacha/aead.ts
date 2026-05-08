/**
 * @module chacha/aead
 * ChaCha20-Poly1305 y XChaCha20-Poly1305 (AEAD).
 *
 * Cifrado autenticado con datos asociados (AEAD) según RFC 8439.
 * Combina ChaCha20 para cifrado con Poly1305 para autenticación.
 *
 * Referencia: https://www.rfc-editor.org/rfc/rfc8439
 */

import { Poly1305 } from "../poly1305"
import { ChaCha20, XChaCha20 } from "./index"
import { clean, abytes } from "../arx"

// ─── Utilidades ──────────────────────────────────────────────────────────────

const ZEROS16 = new Uint8Array(16)
const ZEROS32 = new Uint8Array(32)

/** Compara dos Uint8Array en tiempo constante. */
function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

/** Escribe un u64 LE en un buffer a offset dado. */
function writeU64LE(buf: Uint8Array, val: number, offset: number): void {
  buf[offset + 0] = val & 0xff
  buf[offset + 1] = (val >>> 8) & 0xff
  buf[offset + 2] = (val >>> 16) & 0xff
  buf[offset + 3] = (val >>> 24) & 0xff
  // JavaScript safe integers: val > 2^32 necesitaría Math.floor(val / 2**32)
  // Para longitudes de mensaje razonables (< 4GB) los bytes altos son 0
  buf[offset + 4] = 0
  buf[offset + 5] = 0
  buf[offset + 6] = 0
  buf[offset + 7] = 0
}

/** Pad a 16 bytes al Poly1305. */
function updatePadded(h: Poly1305, msg: Uint8Array): void {
  h.update(msg)
  const leftover = msg.length % 16
  if (leftover) h.update(ZEROS16.subarray(leftover))
}

/** Computa el tag Poly1305 según RFC 8439 §2.8. */
function computeTag(authKey: Uint8Array, ciphertext: Uint8Array, AAD?: Uint8Array): Uint8Array {
  const h = new Poly1305(authKey)
  if (AAD) updatePadded(h, AAD)
  updatePadded(h, ciphertext)

  // Lengths: aad_len || ct_len (ambos u64 LE)
  const lengths = new Uint8Array(16)
  writeU64LE(lengths, AAD ? AAD.length : 0, 0)
  writeU64LE(lengths, ciphertext.length, 8)
  h.update(lengths)

  const tag = h.digest()
  clean(lengths)
  return tag
}

// ─── Tipo AEAD ───────────────────────────────────────────────────────────────

type StreamCipherCtor = new (
  key: Uint8Array,
  nonce: Uint8Array,
  counter?: number
) => {
  encrypt(data: Uint8Array, output?: Uint8Array): Uint8Array
}

// ─── Factory AEAD ────────────────────────────────────────────────────────────

function createAEAD(CipherClass: StreamCipherCtor) {
  return class AEAD {
    private key: Uint8Array
    private nonce: Uint8Array
    private AAD?: Uint8Array
    private tagLength = 16

    constructor(key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array) {
      abytes(key, 32, "key")
      abytes(nonce, undefined, "nonce")
      this.key = key
      this.nonce = nonce
      this.AAD = AAD
    }

    /**
     * Cifra y autentica.
     * Output: ciphertext || tag (16 bytes).
     */
    encrypt(plaintext: Uint8Array): Uint8Array {
      abytes(plaintext, undefined, "plaintext")
      const output = new Uint8Array(plaintext.length + this.tagLength)

      // Copiar plaintext al output
      output.set(plaintext)
      const oPlain = output.subarray(0, plaintext.length)

      // Cifrar in-place con counter=1 (counter=0 se usa para authKey)
      new CipherClass(this.key, this.nonce, 1).encrypt(oPlain, oPlain)

      // Generar authKey: E(key, nonce, counter=0, zeros(32))
      const authKey = new CipherClass(this.key, this.nonce, 0).encrypt(ZEROS32)

      // Computar tag
      const tag = computeTag(authKey, oPlain, this.AAD)
      output.set(tag, plaintext.length)

      clean(authKey, tag)
      return output
    }

    /**
     * Verifica y descifra.
     * Input: ciphertext || tag (16 bytes).
     */
    decrypt(ciphertext: Uint8Array): Uint8Array {
      abytes(ciphertext, undefined, "ciphertext")
      if (ciphertext.length < this.tagLength) throw new Error("aead: ciphertext demasiado corto")

      const data = ciphertext.subarray(0, -this.tagLength)
      const passedTag = ciphertext.subarray(-this.tagLength)

      // Generar authKey
      const authKey = new CipherClass(this.key, this.nonce, 0).encrypt(ZEROS32)

      // Verificar tag
      const tag = computeTag(authKey, data, this.AAD)
      if (!equalBytes(passedTag, tag)) {
        clean(authKey, tag)
        throw new Error("aead: tag inválido")
      }

      // Descifrar con counter=1
      const output = new Uint8Array(data.length)
      output.set(data)
      new CipherClass(this.key, this.nonce, 1).encrypt(output, output)

      clean(authKey, tag)
      return output
    }
  }
}

// ─── ChaCha20-Poly1305 ──────────────────────────────────────────────────────

/**
 * **ChaCha20-Poly1305** — AEAD según RFC 8439.
 *
 * Nonce de 12 bytes. NO es seguro usar nonces aleatorios (colisión en 2^48).
 * Preferir XChaCha20Poly1305 si se necesitan nonces aleatorios.
 *
 * @example
 * ```ts
 * const sealed = new ChaCha20Poly1305(key, nonce, aad).encrypt(plaintext)
 * const opened = new ChaCha20Poly1305(key, nonce, aad).decrypt(sealed)
 * ```
 */
export const ChaCha20Poly1305 = createAEAD(ChaCha20)

/**
 * **XChaCha20-Poly1305** — AEAD con nonce extendido de 24 bytes.
 *
 * Seguro con nonces aleatorios (CSPRNG).
 */
export const XChaCha20Poly1305 = createAEAD(XChaCha20)
