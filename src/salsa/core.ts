/**
 * @module salsa/core
 * Funciones core de Salsa20: quarter-round, salsaCore (desenrollado), hsalsa.
 *
 * Salsa20 es un cifrador de flujo ARX anterior a ChaCha.
 * Cada bloque produce 64 bytes de keystream a partir de:
 *   s[0] | k(4) | s[1] | nonce(2) | cnt(2) | s[2] | k(4) | s[3]
 *
 * Referencia: https://cr.yp.to/snuffle/salsafamily-20071225.pdf
 */

import { rotl } from "../arx"

// ─── Salsa Core (desenrollado) ───────────────────────────────────────────────

/**
 * Genera un bloque de 512 bits (16 u32) de keystream Salsa20.
 * Layout del estado (diferente a ChaCha):
 *   s[0]  k[0]  k[1]  k[2]     "expa" Key    Key    Key
 *   k[3]  s[1]  n[0]  n[1]     Key    "nd 3" Nonce  Nonce
 *   cnt   0     s[2]  k[4]     Pos.   Pos.   "2-by" Key
 *   k[5]  k[6]  k[7]  s[3]     Key    Key    Key    "te k"
 */
// prettier-ignore
export function salsaCore(
  s: Uint32Array, k: Uint32Array, n: Uint32Array, out: Uint32Array, cnt: number, rounds = 20
): void {
  let y00 = s[0], y01 = k[0], y02 = k[1], y03 = k[2],
      y04 = k[3], y05 = s[1], y06 = n[0], y07 = n[1],
      y08 = cnt,  y09 = 0,    y10 = s[2], y11 = k[4],
      y12 = k[5], y13 = k[6], y14 = k[7], y15 = s[3]

  let x00 = y00, x01 = y01, x02 = y02, x03 = y03,
      x04 = y04, x05 = y05, x06 = y06, x07 = y07,
      x08 = y08, x09 = y09, x10 = y10, x11 = y11,
      x12 = y12, x13 = y13, x14 = y14, x15 = y15

  for (let r = 0; r < rounds; r += 2) {
    // Columnas
    x04 ^= rotl(x00 + x12 | 0,  7); x08 ^= rotl(x04 + x00 | 0, 9)
    x12 ^= rotl(x08 + x04 | 0, 13); x00 ^= rotl(x12 + x08 | 0, 18)
    x09 ^= rotl(x05 + x01 | 0,  7); x13 ^= rotl(x09 + x05 | 0, 9)
    x01 ^= rotl(x13 + x09 | 0, 13); x05 ^= rotl(x01 + x13 | 0, 18)
    x14 ^= rotl(x10 + x06 | 0,  7); x02 ^= rotl(x14 + x10 | 0, 9)
    x06 ^= rotl(x02 + x14 | 0, 13); x10 ^= rotl(x06 + x02 | 0, 18)
    x03 ^= rotl(x15 + x11 | 0,  7); x07 ^= rotl(x03 + x15 | 0, 9)
    x11 ^= rotl(x07 + x03 | 0, 13); x15 ^= rotl(x11 + x07 | 0, 18)
    // Filas
    x01 ^= rotl(x00 + x03 | 0,  7); x02 ^= rotl(x01 + x00 | 0, 9)
    x03 ^= rotl(x02 + x01 | 0, 13); x00 ^= rotl(x03 + x02 | 0, 18)
    x06 ^= rotl(x05 + x04 | 0,  7); x07 ^= rotl(x06 + x05 | 0, 9)
    x04 ^= rotl(x07 + x06 | 0, 13); x05 ^= rotl(x04 + x07 | 0, 18)
    x11 ^= rotl(x10 + x09 | 0,  7); x08 ^= rotl(x11 + x10 | 0, 9)
    x09 ^= rotl(x08 + x11 | 0, 13); x10 ^= rotl(x09 + x08 | 0, 18)
    x12 ^= rotl(x15 + x14 | 0,  7); x13 ^= rotl(x12 + x15 | 0, 9)
    x14 ^= rotl(x13 + x12 | 0, 13); x15 ^= rotl(x14 + x13 | 0, 18)
  }

  let oi = 0
  out[oi++] = (y00 + x00) | 0; out[oi++] = (y01 + x01) | 0
  out[oi++] = (y02 + x02) | 0; out[oi++] = (y03 + x03) | 0
  out[oi++] = (y04 + x04) | 0; out[oi++] = (y05 + x05) | 0
  out[oi++] = (y06 + x06) | 0; out[oi++] = (y07 + x07) | 0
  out[oi++] = (y08 + x08) | 0; out[oi++] = (y09 + x09) | 0
  out[oi++] = (y10 + x10) | 0; out[oi++] = (y11 + x11) | 0
  out[oi++] = (y12 + x12) | 0; out[oi++] = (y13 + x13) | 0
  out[oi++] = (y14 + x14) | 0; out[oi++] = (y15 + x15) | 0
}

// ─── HSalsa (para XSalsa20) ─────────────────────────────────────────────────

/**
 * HSalsa: hash de 256 bits que extiende el nonce para XSalsa20.
 * Extrae posiciones [0,5,10,15,6,7,8,9] del estado final (sin sumar y[i]).
 */
// prettier-ignore
export function hsalsa(
  s: Uint32Array, k: Uint32Array, i: Uint32Array, out: Uint32Array
): void {
  let x00 = s[0], x01 = k[0], x02 = k[1], x03 = k[2],
      x04 = k[3], x05 = s[1], x06 = i[0], x07 = i[1],
      x08 = i[2], x09 = i[3], x10 = s[2], x11 = k[4],
      x12 = k[5], x13 = k[6], x14 = k[7], x15 = s[3]

  for (let r = 0; r < 20; r += 2) {
    x04 ^= rotl(x00 + x12 | 0,  7); x08 ^= rotl(x04 + x00 | 0, 9)
    x12 ^= rotl(x08 + x04 | 0, 13); x00 ^= rotl(x12 + x08 | 0, 18)
    x09 ^= rotl(x05 + x01 | 0,  7); x13 ^= rotl(x09 + x05 | 0, 9)
    x01 ^= rotl(x13 + x09 | 0, 13); x05 ^= rotl(x01 + x13 | 0, 18)
    x14 ^= rotl(x10 + x06 | 0,  7); x02 ^= rotl(x14 + x10 | 0, 9)
    x06 ^= rotl(x02 + x14 | 0, 13); x10 ^= rotl(x06 + x02 | 0, 18)
    x03 ^= rotl(x15 + x11 | 0,  7); x07 ^= rotl(x03 + x15 | 0, 9)
    x11 ^= rotl(x07 + x03 | 0, 13); x15 ^= rotl(x11 + x07 | 0, 18)
    x01 ^= rotl(x00 + x03 | 0,  7); x02 ^= rotl(x01 + x00 | 0, 9)
    x03 ^= rotl(x02 + x01 | 0, 13); x00 ^= rotl(x03 + x02 | 0, 18)
    x06 ^= rotl(x05 + x04 | 0,  7); x07 ^= rotl(x06 + x05 | 0, 9)
    x04 ^= rotl(x07 + x06 | 0, 13); x05 ^= rotl(x04 + x07 | 0, 18)
    x11 ^= rotl(x10 + x09 | 0,  7); x08 ^= rotl(x11 + x10 | 0, 9)
    x09 ^= rotl(x08 + x11 | 0, 13); x10 ^= rotl(x09 + x08 | 0, 18)
    x12 ^= rotl(x15 + x14 | 0,  7); x13 ^= rotl(x12 + x15 | 0, 9)
    x14 ^= rotl(x13 + x12 | 0, 13); x15 ^= rotl(x14 + x13 | 0, 18)
  }

  let oi = 0
  out[oi++] = x00; out[oi++] = x05
  out[oi++] = x10; out[oi++] = x15
  out[oi++] = x06; out[oi++] = x07
  out[oi++] = x08; out[oi++] = x09
}
