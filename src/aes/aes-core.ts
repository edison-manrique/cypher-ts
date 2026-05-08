/**
 * @module aes-core
 * Núcleo del cifrado AES: Key Expansion, encriptación y desencriptación de bloques.
 *
 * Implementación optimizada con T-tables fusionadas (T01/T23).
 * Soporta claves de 128, 192 y 256 bits.
 */

import { BLOCK_SIZE32, tableEncoding, tableDecoding, xPowers, rotr32_8 } from "./constants"
import { abytes, u32, clean, isAligned32, copyBytes } from "./utils"

// ─── Validación de clave ─────────────────────────────────────────────────────

/** Valida que la clave AES sea de 16, 24 o 32 bytes. */
export function validateKeyLength(key: Uint8Array): void {
  if (![16, 24, 32].includes(key.length))
    throw new Error('"aes key" se esperaba Uint8Array de longitud 16/24/32, longitud=' + key.length)
}

// ─── Funciones de aplicación de tablas ───────────────────────────────────────

/**
 * Aplica las tablas fusionadas T01 y T23 para una posición de ronda.
 * Combina SubBytes + ShiftRows + MixColumns en un solo paso.
 */
function apply0123(T01: Uint32Array, T23: Uint32Array, s0: number, s1: number, s2: number, s3: number): number {
  return T01[((s0 << 8) & 0xff00) | ((s1 >>> 8) & 0xff)] ^ T23[((s2 >>> 8) & 0xff00) | ((s3 >>> 24) & 0xff)]
}

/**
 * Aplica el S-box comprimido (sbox2) para la última ronda (sin MixColumns).
 */
function applySbox(sbox2: Uint16Array, s0: number, s1: number, s2: number, s3: number): number {
  return sbox2[(s0 & 0xff) | (s1 & 0xff00)] | (sbox2[((s2 >>> 16) & 0xff) | ((s3 >>> 16) & 0xff00)] << 16)
}

// ─── Key Expansion ───────────────────────────────────────────────────────────

/**
 * Expansión de clave para cifrado (little-endian).
 * Genera las round keys a partir de la clave original.
 *
 * @param key - Clave AES de 16/24/32 bytes
 * @returns Uint32Array con las round keys expandidas
 */
export function expandKeyLE(key: Uint8Array): Uint32Array {
  abytes(key)
  validateKeyLength(key)
  const { sbox2 } = tableEncoding
  const toClean: Uint8Array[] = []
  if (!isAligned32(key)) toClean.push((key = copyBytes(key)))
  const k32 = u32(key)
  const Nk = k32.length
  const subByte = (n: number) => applySbox(sbox2, n, n, n, n)
  const xk = new Uint32Array(key.length + 28)
  xk.set(k32)
  for (let i = Nk; i < xk.length; i++) {
    let t = xk[i - 1]
    if (i % Nk === 0) t = subByte(rotr32_8(t)) ^ xPowers[i / Nk - 1]
    else if (Nk > 6 && i % Nk === 4) t = subByte(t)
    xk[i] = xk[i - Nk] ^ t
  }
  clean(...toClean)
  return xk
}

/**
 * Expansión de clave para descifrado (little-endian).
 * Aplica InvMixColumns a las round keys intermedias.
 *
 * @param key - Clave AES de 16/24/32 bytes
 * @returns Uint32Array con las round keys invertidas
 */
export function expandKeyDecLE(key: Uint8Array): Uint32Array {
  const encKey = expandKeyLE(key)
  const xk = encKey.slice()
  const Nk = encKey.length
  const { sbox2 } = tableEncoding
  const { T0, T1, T2, T3 } = tableDecoding
  // Invertir las claves por chunks de 4 (rondas)
  for (let i = 0; i < Nk; i += 4) {
    for (let j = 0; j < 4; j++) xk[i + j] = encKey[Nk - i - 4 + j]
  }
  clean(encKey)
  // Aplicar InvMixColumn excepto primera y última ronda
  for (let i = BLOCK_SIZE32; i < Nk - BLOCK_SIZE32; i++) {
    const x = xk[i]
    const w = applySbox(sbox2, x, x, x, x)
    xk[i] = T0[w & 0xff] ^ T1[(w >>> 8) & 0xff] ^ T2[(w >>> 16) & 0xff] ^ T3[w >>> 24]
  }
  return xk
}

// ─── Cifrado / Descifrado de bloque ──────────────────────────────────────────

/**
 * Cifra un bloque AES (4 words de 32 bits).
 *
 * @param xk - Round keys expandidas
 * @param s0,s1,s2,s3 - State words del bloque de entrada
 * @returns State words del bloque cifrado
 */
export function encryptBlock(
  xk: Uint32Array,
  s0: number,
  s1: number,
  s2: number,
  s3: number
): { s0: number; s1: number; s2: number; s3: number } {
  const { sbox2, T01, T23 } = tableEncoding
  let k = 0
  // AddRoundKey inicial
  s0 ^= xk[k++]
  s1 ^= xk[k++]
  s2 ^= xk[k++]
  s3 ^= xk[k++]
  const rounds = xk.length / 4 - 2
  // Rondas intermedias (SubBytes + ShiftRows + MixColumns + AddRoundKey)
  for (let i = 0; i < rounds; i++) {
    const t0 = xk[k++] ^ apply0123(T01, T23, s0, s1, s2, s3)
    const t1 = xk[k++] ^ apply0123(T01, T23, s1, s2, s3, s0)
    const t2 = xk[k++] ^ apply0123(T01, T23, s2, s3, s0, s1)
    const t3 = xk[k++] ^ apply0123(T01, T23, s3, s0, s1, s2)
    s0 = t0
    s1 = t1
    s2 = t2
    s3 = t3
  }
  // Última ronda (sin MixColumns, usando sbox2)
  const t0 = xk[k++] ^ applySbox(sbox2, s0, s1, s2, s3)
  const t1 = xk[k++] ^ applySbox(sbox2, s1, s2, s3, s0)
  const t2 = xk[k++] ^ applySbox(sbox2, s2, s3, s0, s1)
  const t3 = xk[k++] ^ applySbox(sbox2, s3, s0, s1, s2)
  return { s0: t0, s1: t1, s2: t2, s3: t3 }
}

/**
 * Cifra un bloque AES in-place sobre un Uint8Array de 16 bytes.
 * Útil para CMAC y otros modos que operan directamente sobre buffers.
 *
 * @param xk - Round keys expandidas
 * @param block - Buffer de 16 bytes (modificado in-place)
 */
export function encryptBlockInPlace(xk: Uint32Array, block: Uint8Array): Uint8Array {
  const b32 = u32(block)
  const { s0, s1, s2, s3 } = encryptBlock(xk, b32[0], b32[1], b32[2], b32[3])
  b32[0] = s0
  b32[1] = s1
  b32[2] = s2
  b32[3] = s3
  return block
}

/**
 * Descifra un bloque AES (4 words de 32 bits).
 * Las posiciones de los argumentos son diferentes a encrypt (InvShiftRows).
 *
 * @param xk - Round keys invertidas
 * @param s0,s1,s2,s3 - State words del bloque cifrado
 * @returns State words del bloque descifrado
 */
export function decryptBlock(
  xk: Uint32Array,
  s0: number,
  s1: number,
  s2: number,
  s3: number
): { s0: number; s1: number; s2: number; s3: number } {
  const { sbox2, T01, T23 } = tableDecoding
  let k = 0
  // AddRoundKey inicial
  s0 ^= xk[k++]
  s1 ^= xk[k++]
  s2 ^= xk[k++]
  s3 ^= xk[k++]
  const rounds = xk.length / 4 - 2
  // Rondas intermedias (InvSubBytes + InvShiftRows + InvMixColumns + AddRoundKey)
  for (let i = 0; i < rounds; i++) {
    const t0 = xk[k++] ^ apply0123(T01, T23, s0, s3, s2, s1)
    const t1 = xk[k++] ^ apply0123(T01, T23, s1, s0, s3, s2)
    const t2 = xk[k++] ^ apply0123(T01, T23, s2, s1, s0, s3)
    const t3 = xk[k++] ^ apply0123(T01, T23, s3, s2, s1, s0)
    s0 = t0
    s1 = t1
    s2 = t2
    s3 = t3
  }
  // Última ronda (sin InvMixColumns)
  const t0 = xk[k++] ^ applySbox(sbox2, s0, s3, s2, s1)
  const t1 = xk[k++] ^ applySbox(sbox2, s1, s0, s3, s2)
  const t2 = xk[k++] ^ applySbox(sbox2, s2, s1, s0, s3)
  const t3 = xk[k++] ^ applySbox(sbox2, s3, s2, s1, s0)
  return { s0: t0, s1: t1, s2: t2, s3: t3 }
}
