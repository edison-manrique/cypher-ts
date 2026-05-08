/**
 * @module chacha/index
 * Cifrados de flujo ChaCha: ChaCha20, XChaCha20, ChaCha8, ChaCha12.
 *
 * Variantes:
 * - ChaCha20:     RFC 8439, nonce 12 bytes, counter 4 bytes
 * - XChaCha20:    nonce extendido 24 bytes (seguro con nonces aleatorios)
 * - ChaCha20Orig: original DJB, nonce 8 bytes, counter 8 bytes
 * - ChaCha8/12:   variantes reducidas en rondas
 *
 * Todas implementadas como clases.
 */

import { runCipher, prepareKey, clean, abytes, u32, copyBytes, isAligned32, MAX_COUNTER } from "../arx"
import { chachaCore, hchacha } from "./core"

// ─── Clase ChaCha20 (RFC 8439) ──────────────────────────────────────────────

/**
 * **ChaCha20** — cifrador de flujo RFC 8439.
 *
 * Nonce de 12 bytes, counter de 4 bytes (máximo ~256 GB por nonce).
 * Usado en TLS 1.3.
 *
 * @example
 * ```ts
 * const c = new ChaCha20(key, nonce)
 * const encrypted = c.encrypt(data)
 * const decrypted = new ChaCha20(key, nonce).encrypt(encrypted)
 * ```
 */
export class ChaCha20 {
  private sigma: Uint32Array
  private k: Uint8Array
  private n32: Uint32Array
  private counter: number
  private rounds: number

  constructor(key: Uint8Array, nonce: Uint8Array, counter = 0, rounds = 20) {
    abytes(key, undefined, "key")
    abytes(nonce, 12, "nonce")
    if (counter < 0 || counter >= MAX_COUNTER) throw new Error("chacha20: contador inválido")
    const { sigma, k } = prepareKey(key, false)
    this.sigma = sigma
    this.k = k
    if (!isAligned32(nonce)) nonce = copyBytes(nonce)
    this.n32 = u32(nonce)
    this.counter = counter
    this.rounds = rounds
  }

  /** Cifra/descifra datos (XOR con keystream). Encrypt = Decrypt. */
  encrypt(data: Uint8Array, output?: Uint8Array): Uint8Array {
    abytes(data, undefined, "data")
    if (!output) output = new Uint8Array(data.length)
    const k32 = u32(this.k)
    runCipher(chachaCore, this.sigma, k32, this.n32, data, output, this.counter, this.rounds)
    clean(this.k)
    return output
  }

  decrypt(data: Uint8Array, output?: Uint8Array): Uint8Array {
    return this.encrypt(data, output)
  }
}

// ─── Clase XChaCha20 ─────────────────────────────────────────────────────────

/**
 * **XChaCha20** — variante con nonce extendido de 24 bytes.
 *
 * Seguro para nonces aleatorios (CSPRNG). Usa HChaCha para derivar
 * una subclave de 256 bits a partir de los primeros 16 bytes del nonce.
 */
export class XChaCha20 {
  private sigma: Uint32Array
  private k: Uint8Array
  private n32: Uint32Array
  private counter: number
  private rounds: number

  constructor(key: Uint8Array, nonce: Uint8Array, counter = 0, rounds = 20) {
    abytes(key, undefined, "key")
    abytes(nonce, 24, "nonce")
    if (counter < 0 || counter >= MAX_COUNTER) throw new Error("xchacha20: contador inválido")

    const { sigma, k } = prepareKey(key, false)
    const k32 = u32(k)

    // HChaCha: key(32) + nonce[0..16] → key'(32)
    if (!isAligned32(nonce)) nonce = copyBytes(nonce)
    hchacha(sigma, k32, u32(nonce.subarray(0, 16)), k32)

    // Nonce restante: nonce[16..24] → padded a 12 bytes (4 zeros + 8 bytes)
    const nc = new Uint8Array(12)
    nc.set(nonce.subarray(16), 4)

    this.sigma = sigma
    this.k = k
    this.n32 = u32(nc)
    this.counter = counter
    this.rounds = rounds
  }

  encrypt(data: Uint8Array, output?: Uint8Array): Uint8Array {
    abytes(data, undefined, "data")
    if (!output) output = new Uint8Array(data.length)
    const k32 = u32(this.k)
    runCipher(chachaCore, this.sigma, k32, this.n32, data, output, this.counter, this.rounds)
    clean(this.k)
    return output
  }

  decrypt(data: Uint8Array, output?: Uint8Array): Uint8Array {
    return this.encrypt(data, output)
  }
}

// ─── Variantes reducidas ─────────────────────────────────────────────────────

/** ChaCha8: 8 rondas (más rápido, menor margen de seguridad). */
export class ChaCha8 extends ChaCha20 {
  constructor(key: Uint8Array, nonce: Uint8Array, counter = 0) {
    super(key, nonce, counter, 8)
  }
}

/** ChaCha12: 12 rondas (balance velocidad/seguridad). */
export class ChaCha12 extends ChaCha20 {
  constructor(key: Uint8Array, nonce: Uint8Array, counter = 0) {
    super(key, nonce, counter, 12)
  }
}
