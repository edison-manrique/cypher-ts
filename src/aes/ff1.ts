/**
 * @module aes/ff1
 * FPE-FF1: Cifrado que preserva formato (Format-Preserving Encryption).
 *
 * Especificado en NIST SP 800-38G.
 * Cifra datos preservando su formato original (ej: números de tarjeta,
 * SSN, etc.). La salida tiene el mismo conjunto de caracteres y longitud.
 *
 * Usa AES como primitiva PRF interna, con una red de Feistel de 10 rondas.
 *
 * Referencia: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf
 */

import { expandKeyLE, encryptBlockInPlace } from "./aes-core"
import { abytes, clean, bytesToNumberBE, numberToBytesBE } from "./utils"

const BLOCK_LEN = 16

// ─── Utilidades internas ─────────────────────────────────────────────────────

/** Módulo correcto para números negativos. */
function mod(a: number, b: number): number
function mod(a: bigint, b: bigint): bigint
function mod(a: any, b: any): number | bigint {
  const result = a % b
  return result >= 0 ? result : b + result
}

/** Convierte array de dígitos en base `radix` a BigInt. */
function NUMradix(radix: number, data: number[]): bigint {
  let res = 0n
  for (const d of data) res = res * BigInt(radix) + BigInt(d)
  return res
}

// ─── Núcleo de la ronda FF1 ──────────────────────────────────────────────────

function createRound(radix: number, key: Uint8Array, tweak: Uint8Array, x: number[]) {
  if (radix > 2 ** 16 - 1) throw new Error("ff1: radix inválido " + radix)

  // radix**minlen ≥ 100
  const minLen = Math.ceil(Math.log(100) / Math.log(radix))
  const maxLen = 2 ** 32 - 1

  if (2 > minLen || minLen > maxLen || maxLen >= 2 ** 32)
    throw new Error("ff1: radix inválido: 2 ≤ minlen ≤ maxlen < 2**32")
  if (!Array.isArray(x)) throw new Error("ff1: X debe ser un array")
  if (x.length < minLen || x.length > maxLen) throw new Error("ff1: X fuera de los límites minLen..maxLen")

  const u = Math.floor(x.length / 2)
  const v = x.length - u
  const b = Math.ceil(Math.ceil(v * Math.log2(radix)) / 8)
  const d = 4 * Math.ceil(b / 4) + 4
  const padding = mod(-tweak.length - b - 1, 16)

  // P = [1]1 || [2]1 || [1]1 || [radix]3 || [10]1 || [u mod 256]1 || [n]4 || [t]4
  const P = Uint8Array.from([1, 2, 1, 0, 0, 0, 10, u, 0, 0, 0, 0, 0, 0, 0, 0])
  const view = new DataView(P.buffer)
  view.setUint16(4, radix, false)
  view.setUint32(8, x.length, false)
  view.setUint32(12, tweak.length, false)

  // Q = T || [0](−t−b−1) mod 16 || [i]1 || [NUMradix(B)]b
  const PQ = new Uint8Array(P.length + tweak.length + padding + 1 + b)
  PQ.set(P)
  clean(P)
  PQ.set(tweak, BLOCK_LEN)

  const xk = expandKeyLE(key)

  const round = (A: number[], B: number[], i: number, decrypt = false) => {
    // Q = ... || [i]1 || [NUMradix(B)]b
    PQ[PQ.length - b - 1] = i
    if (b) PQ.set(numberToBytesBE(NUMradix(radix, B), b), PQ.length - b)

    // PRF: AES-CBC-MAC sobre PQ
    const r = new Uint8Array(16)
    for (let j = 0; j < PQ.length / BLOCK_LEN; j++) {
      for (let k = 0; k < BLOCK_LEN; k++) r[k] ^= PQ[j * BLOCK_LEN + k]
      encryptBlockInPlace(xk, r)
    }

    // S = R || CIPHK(R ⊕ [1]16) || CIPHK(R ⊕ [2]16) || ...
    let s = Array.from(r)
    for (let j = 1; s.length < d; j++) {
      const block = numberToBytesBE(BigInt(j), 16)
      for (let k = 0; k < BLOCK_LEN; k++) block[k] ^= r[k]
      s.push(...Array.from(encryptBlockInPlace(xk, block)))
    }

    let y = bytesToNumberBE(Uint8Array.from(s.slice(0, d)))
    s.fill(0)

    if (decrypt) y = -y

    const m = i % 2 === 0 ? u : v
    let c = mod(NUMradix(radix, A) + y, BigInt(radix) ** BigInt(m))

    // STR(radix, m, c)
    const C = Array(m).fill(0)
    for (let k = 0; k < m; k++, c /= BigInt(radix)) C[m - 1 - k] = Number(c % BigInt(radix))

    A.fill(0)
    A = B
    B = C
    return [A, B]
  }

  const destroy = () => {
    clean(xk, PQ)
  }

  return { u, round, destroy }
}

// ─── Clase FF1 ───────────────────────────────────────────────────────────────

/**
 * **FF1** — Cifrado que preserva formato (FPE).
 *
 * Cifra un array de dígitos en base `radix`, preservando:
 * - Longitud del array
 * - Rango de valores [0, radix)
 *
 * @example
 * ```ts
 * // Cifrar un número de tarjeta (base 10)
 * const ff1 = new FF1(10, key)
 * const encrypted = ff1.encrypt([0,1,2,3,4,5,6,7,8,9])
 * // → [2,4,3,3,4,7,7,4,8,4]
 *
 * const decrypted = ff1.decrypt(encrypted)
 * // → [0,1,2,3,4,5,6,7,8,9]
 * ```
 */
export class FF1 {
  private radix: number
  private key: Uint8Array
  private tweak: Uint8Array

  constructor(radix: number, key: Uint8Array, tweak: Uint8Array = new Uint8Array(0)) {
    if (typeof radix !== "number" || !Number.isInteger(radix) || radix < 2)
      throw new Error("ff1: radix debe ser un entero >= 2")
    abytes(key, undefined, "key")
    abytes(tweak, undefined, "tweak")
    this.radix = radix
    this.key = key
    this.tweak = tweak
  }

  /** Cifra un array de dígitos en base `radix`. */
  encrypt(x: number[]): number[] {
    const { u, round, destroy } = createRound(this.radix, this.key, this.tweak, x)
    let [A, B] = [x.slice(0, u), x.slice(u)]
    for (let i = 0; i < 10; i++) [A, B] = round(A, B, i)
    destroy()
    const res = A.concat(B)
    A.fill(0)
    B.fill(0)
    return res
  }

  /** Descifra un array de dígitos en base `radix`. */
  decrypt(x: number[]): number[] {
    const { u, round, destroy } = createRound(this.radix, this.key, this.tweak, x)
    // Decrypt: índices invertidos, A/B intercambiados, substracción en vez de adición
    let [B, A] = [x.slice(0, u), x.slice(u)]
    for (let i = 9; i >= 0; i--) [A, B] = round(A, B, i, true)
    destroy()
    const res = B.concat(A)
    A.fill(0)
    B.fill(0)
    return res
  }
}

// ─── BinaryFF1 ───────────────────────────────────────────────────────────────

/** Codificación binaria LE: cada byte → 8 bits en little-endian. */
const binLE = {
  encode(bytes: Uint8Array): number[] {
    const x: number[] = []
    for (let i = 0; i < bytes.length; i++) {
      for (let j = 0, tmp = bytes[i]; j < 8; j++, tmp >>= 1) x.push(tmp & 1)
    }
    return x
  },
  decode(b: number[]): Uint8Array {
    if (!Array.isArray(b) || b.length % 8) throw new Error("ff1: binary string inválido")
    const res = new Uint8Array(b.length / 8)
    for (let i = 0, j = 0; i < res.length; i++) {
      res[i] = b[j++] | (b[j++] << 1) | (b[j++] << 2) | (b[j++] << 3)
      res[i] |= (b[j++] << 4) | (b[j++] << 5) | (b[j++] << 6) | (b[j++] << 7)
    }
    return res
  }
}

/**
 * **BinaryFF1** — FF1 para datos binarios.
 *
 * Convierte bytes a bits, aplica FF1 con radix=2, y reconvierte.
 *
 * @example
 * ```ts
 * const bff1 = new BinaryFF1(key)
 * const enc = bff1.encrypt(data)
 * const dec = bff1.decrypt(enc)
 * ```
 */
export class BinaryFF1 {
  private ff1: FF1

  constructor(key: Uint8Array, tweak: Uint8Array = new Uint8Array(0)) {
    this.ff1 = new FF1(2, key, tweak)
  }

  encrypt(data: Uint8Array): Uint8Array {
    return binLE.decode(this.ff1.encrypt(binLE.encode(data)))
  }

  decrypt(data: Uint8Array): Uint8Array {
    return binLE.decode(this.ff1.decrypt(binLE.encode(data)))
  }
}
