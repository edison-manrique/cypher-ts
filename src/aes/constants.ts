/**
 * @module constants
 * Constantes del algoritmo AES: S-box, S-box invertido, T-tables, potencias de x.
 *
 * Las T-tables combinan SubBytes, ShiftRows y MixColumns en una sola lookup,
 * siguiendo la optimización 5.2 de la propuesta original de Rijndael.
 *
 * Optimización clave vs noble-ciphers:
 * - T0+T1 se fusionan en T01 (índice u16), T2+T3 en T23
 * - sbox2 comprime dos lookups de S-box en un solo acceso u16
 */

import { clean } from "./utils"

// ─── Constantes de bloque ────────────────────────────────────────────────────

export const BLOCK_SIZE = 16
export const BLOCK_SIZE32 = 4
export const POLY = 0x11b // Polinomio irreducible: x^8 + x^4 + x^3 + x + 1

// ─── Aritmética GF(2^8) ─────────────────────────────────────────────────────

/** Multiplicación por 2 en GF(2^8) (xtime). */
export function mul2(n: number): number {
  return (n << 1) ^ (POLY & -(n >> 7))
}

/** Multiplicación en GF(2^8) con método de Montgomery ladder. */
export function mul(a: number, b: number): number {
  let res = 0
  for (; b > 0; b >>= 1) {
    res ^= a & -(b & 1) // if (b&1) res ^= a (constante en tiempo)
    a = mul2(a)
  }
  return res
}

// ─── S-box ───────────────────────────────────────────────────────────────────

/**
 * Genera el S-box de AES.
 * Se calcula usando inversión en campo finito GF(2^8)
 * seguido de una transformación afín y XOR con 0x63.
 */
export const sbox: Uint8Array = (() => {
  const t = new Uint8Array(256)
  for (let i = 0, x = 1; i < 256; i++, x ^= mul2(x)) t[i] = x
  const box = new Uint8Array(256)
  box[0] = 0x63
  for (let i = 0; i < 255; i++) {
    let x = t[255 - i]
    x |= x << 8
    box[t[i]] = (x ^ (x >> 4) ^ (x >> 5) ^ (x >> 6) ^ (x >> 7) ^ 0x63) & 0xff
  }
  clean(t)
  return box
})()

/** S-box invertido (para descifrado). */
export const invSbox: Uint8Array = sbox.map((_, j) => sbox.indexOf(j))

// ─── Rotaciones de u32 ──────────────────────────────────────────────────────

/** Rota u32 a la derecha por 8 bits. */
export function rotr32_8(n: number): number {
  return (n << 24) | (n >>> 8)
}

/** Rota u32 a la izquierda por 8 bits. */
export function rotl32_8(n: number): number {
  return (n << 8) | (n >>> 24)
}

// ─── T-tables ────────────────────────────────────────────────────────────────

/**
 * Genera T-tables optimizadas para AES.
 *
 * Las tablas T01 y T23 fusionan pares de tablas individuales (T0+T1, T2+T3)
 * usando índice u16, reduciendo la cantidad de lookups por ronda.
 * sbox2 comprime dos aplicaciones del S-box en una sola operación u16.
 */
function genTtable(sboxArr: Uint8Array, fn: (n: number) => number) {
  if (sboxArr.length !== 256) throw new Error("S-box de longitud incorrecta")
  const T0 = new Uint32Array(256).map((_, j) => fn(sboxArr[j]))
  const T1 = T0.map(rotl32_8)
  const T2 = T1.map(rotl32_8)
  const T3 = T2.map(rotl32_8)
  const T01 = new Uint32Array(256 * 256)
  const T23 = new Uint32Array(256 * 256)
  const sbox2 = new Uint16Array(256 * 256)
  for (let i = 0; i < 256; i++) {
    for (let j = 0; j < 256; j++) {
      const idx = i * 256 + j
      T01[idx] = T0[i] ^ T1[j]
      T23[idx] = T2[i] ^ T3[j]
      sbox2[idx] = (sboxArr[i] << 8) | sboxArr[j]
    }
  }
  return { sbox: sboxArr, sbox2, T0, T1, T2, T3, T01, T23 }
}

/** Tablas de cifrado (SubBytes + ShiftRows + MixColumns). */
export const tableEncoding = genTtable(sbox, (s: number) => (mul(s, 3) << 24) | (s << 16) | (s << 8) | mul(s, 2))

/** Tablas de descifrado (InvSubBytes + InvShiftRows + InvMixColumns). */
export const tableDecoding = genTtable(
  invSbox,
  (s) => (mul(s, 11) << 24) | (mul(s, 13) << 16) | (mul(s, 9) << 8) | mul(s, 14)
)

/** Potencias de x (rcon) para key expansion. */
export const xPowers: Uint8Array = (() => {
  const p = new Uint8Array(16)
  for (let i = 0, x = 1; i < 16; i++, x = mul2(x)) p[i] = x
  return p
})()
