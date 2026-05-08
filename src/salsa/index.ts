/**
 * @module salsa/index
 * Cifrados de flujo Salsa20 y XSalsa20.
 *
 * Variantes:
 * - Salsa20:   nonce 8 bytes, counter 8 bytes (original DJB)
 * - XSalsa20:  nonce 24 bytes (seguro con nonces aleatorios)
 *
 * Todas implementadas como clases.
 */

import { runCipher, prepareKey, clean, abytes, u32, copyBytes, isAligned32, MAX_COUNTER } from "../arx"
import { salsaCore, hsalsa } from "./core"

// ─── Clase Salsa20 ───────────────────────────────────────────────────────────

/**
 * **Salsa20** — cifrador de flujo original de DJB.
 *
 * Nonce de 8 bytes. Acepta claves de 32 o 16 bytes.
 * El counter ocupa los últimos 8 bytes del estado (posiciones 8-9).
 *
 * @example
 * ```ts
 * const c = new Salsa20(key, nonce)
 * const encrypted = c.encrypt(data)
 * ```
 */
export class Salsa20 {
  private sigma: Uint32Array
  private k: Uint8Array
  private n32: Uint32Array
  private counter: number
  private rounds: number

  constructor(key: Uint8Array, nonce: Uint8Array, counter = 0, rounds = 20) {
    abytes(key, undefined, "key")
    abytes(nonce, 8, "nonce")
    if (counter < 0 || counter >= MAX_COUNTER) throw new Error("salsa20: contador inválido")

    const { sigma, k } = prepareKey(key, true)
    this.sigma = sigma
    this.k = k

    // Salsa: counterRight=true, counterLength=8
    // nonceNcLen = 16-8 = 8 → nonce de 8 bytes
    // Se padea a 12 bytes: nc.set(nonce, counterRight ? 0 : 12-nonce.length)
    // counterRight=true → nonce al inicio
    if (!isAligned32(nonce)) nonce = copyBytes(nonce)
    const nc = new Uint8Array(12)
    nc.set(nonce, 0) // counterRight: nonce al inicio
    this.n32 = u32(nc)
    this.counter = counter
    this.rounds = rounds
  }

  /** Cifra/descifra datos (XOR con keystream). */
  encrypt(data: Uint8Array, output?: Uint8Array): Uint8Array {
    abytes(data, undefined, "data")
    if (!output) output = new Uint8Array(data.length)
    const k32 = u32(this.k)
    runCipher(salsaCore, this.sigma, k32, this.n32, data, output, this.counter, this.rounds)
    clean(this.k)
    return output
  }

  decrypt(data: Uint8Array, output?: Uint8Array): Uint8Array {
    return this.encrypt(data, output)
  }
}

// ─── Clase XSalsa20 ──────────────────────────────────────────────────────────

/**
 * **XSalsa20** — variante con nonce extendido de 24 bytes.
 *
 * Seguro para nonces aleatorios (CSPRNG). Usa HSalsa para derivar
 * una subclave de 256 bits a partir de los primeros 16 bytes del nonce.
 */
export class XSalsa20 {
  private sigma: Uint32Array
  private k: Uint8Array
  private n32: Uint32Array
  private counter: number
  private rounds: number

  constructor(key: Uint8Array, nonce: Uint8Array, counter = 0, rounds = 20) {
    abytes(key, undefined, "key")
    abytes(nonce, 24, "nonce")
    if (counter < 0 || counter >= MAX_COUNTER) throw new Error("xsalsa20: contador inválido")

    const { sigma, k } = prepareKey(key, false)
    const k32 = u32(k)

    // HSalsa: key(32) + nonce[0..16] → key'(32)
    if (!isAligned32(nonce)) nonce = copyBytes(nonce)
    hsalsa(sigma, k32, u32(nonce.subarray(0, 16)), k32)

    // Nonce restante: nonce[16..24] → padded a 12 bytes (counterRight: al inicio)
    const nc = new Uint8Array(12)
    nc.set(nonce.subarray(16), 0) // counterRight: nonce al inicio

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
    runCipher(salsaCore, this.sigma, k32, this.n32, data, output, this.counter, this.rounds)
    clean(this.k)
    return output
  }

  decrypt(data: Uint8Array, output?: Uint8Array): Uint8Array {
    return this.encrypt(data, output)
  }
}
