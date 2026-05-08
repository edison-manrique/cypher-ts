/**
 * @module chacha/core
 * Funciones core de ChaCha: quarter-round, chachaCore (desenrollado), hchacha.
 *
 * ChaCha es un cifrador de flujo basado en ARX (Add-Rotate-XOR).
 * Cada bloque produce 64 bytes de keystream a partir de:
 *   sigma(4) | key(8) | counter(1) | nonce(3)
 *
 * Referencia: https://cr.yp.to/chacha/chacha-20080128.pdf
 * RFC 8439: https://www.rfc-editor.org/rfc/rfc8439
 */

import { rotl } from "../arx"

// ─── ChaCha Core (desenrollado, ~4x más rápido que versión con loop) ─────────

/**
 * Genera un bloque de 512 bits (16 u32) de keystream ChaCha.
 * Layout del estado:
 *   s[0..3]  = constantes sigma ("expand 32-byte k")
 *   k[0..7]  = clave (256 bits)
 *   cnt      = contador de bloque (32 bits)
 *   n[0..2]  = nonce (96 bits)
 */
// prettier-ignore
export function chachaCore(
  s: Uint32Array, k: Uint32Array, n: Uint32Array, out: Uint32Array, cnt: number, rounds = 20
): void {
  let y00 = s[0], y01 = s[1], y02 = s[2], y03 = s[3],
      y04 = k[0], y05 = k[1], y06 = k[2], y07 = k[3],
      y08 = k[4], y09 = k[5], y10 = k[6], y11 = k[7],
      y12 = cnt,  y13 = n[0], y14 = n[1], y15 = n[2]

  let x00 = y00, x01 = y01, x02 = y02, x03 = y03,
      x04 = y04, x05 = y05, x06 = y06, x07 = y07,
      x08 = y08, x09 = y09, x10 = y10, x11 = y11,
      x12 = y12, x13 = y13, x14 = y14, x15 = y15

  for (let r = 0; r < rounds; r += 2) {
    // Columnas
    x00 = (x00 + x04) | 0; x12 = rotl(x12 ^ x00, 16)
    x08 = (x08 + x12) | 0; x04 = rotl(x04 ^ x08, 12)
    x00 = (x00 + x04) | 0; x12 = rotl(x12 ^ x00, 8)
    x08 = (x08 + x12) | 0; x04 = rotl(x04 ^ x08, 7)

    x01 = (x01 + x05) | 0; x13 = rotl(x13 ^ x01, 16)
    x09 = (x09 + x13) | 0; x05 = rotl(x05 ^ x09, 12)
    x01 = (x01 + x05) | 0; x13 = rotl(x13 ^ x01, 8)
    x09 = (x09 + x13) | 0; x05 = rotl(x05 ^ x09, 7)

    x02 = (x02 + x06) | 0; x14 = rotl(x14 ^ x02, 16)
    x10 = (x10 + x14) | 0; x06 = rotl(x06 ^ x10, 12)
    x02 = (x02 + x06) | 0; x14 = rotl(x14 ^ x02, 8)
    x10 = (x10 + x14) | 0; x06 = rotl(x06 ^ x10, 7)

    x03 = (x03 + x07) | 0; x15 = rotl(x15 ^ x03, 16)
    x11 = (x11 + x15) | 0; x07 = rotl(x07 ^ x11, 12)
    x03 = (x03 + x07) | 0; x15 = rotl(x15 ^ x03, 8)
    x11 = (x11 + x15) | 0; x07 = rotl(x07 ^ x11, 7)

    // Diagonales
    x00 = (x00 + x05) | 0; x15 = rotl(x15 ^ x00, 16)
    x10 = (x10 + x15) | 0; x05 = rotl(x05 ^ x10, 12)
    x00 = (x00 + x05) | 0; x15 = rotl(x15 ^ x00, 8)
    x10 = (x10 + x15) | 0; x05 = rotl(x05 ^ x10, 7)

    x01 = (x01 + x06) | 0; x12 = rotl(x12 ^ x01, 16)
    x11 = (x11 + x12) | 0; x06 = rotl(x06 ^ x11, 12)
    x01 = (x01 + x06) | 0; x12 = rotl(x12 ^ x01, 8)
    x11 = (x11 + x12) | 0; x06 = rotl(x06 ^ x11, 7)

    x02 = (x02 + x07) | 0; x13 = rotl(x13 ^ x02, 16)
    x08 = (x08 + x13) | 0; x07 = rotl(x07 ^ x08, 12)
    x02 = (x02 + x07) | 0; x13 = rotl(x13 ^ x02, 8)
    x08 = (x08 + x13) | 0; x07 = rotl(x07 ^ x08, 7)

    x03 = (x03 + x04) | 0; x14 = rotl(x14 ^ x03, 16)
    x09 = (x09 + x14) | 0; x04 = rotl(x04 ^ x09, 12)
    x03 = (x03 + x04) | 0; x14 = rotl(x14 ^ x03, 8)
    x09 = (x09 + x14) | 0; x04 = rotl(x04 ^ x09, 7)
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

// ─── HChaCha (para XChaCha20) ────────────────────────────────────────────────

/**
 * HChaCha: hash de 256 bits que extiende el nonce para XChaCha20.
 * Toma key(32 bytes) + nonce(16 bytes) → key'(32 bytes).
 * Extrae las posiciones [0,1,2,3,12,13,14,15] del estado final.
 */
// prettier-ignore
export function hchacha(
  s: Uint32Array, k: Uint32Array, i: Uint32Array, out: Uint32Array
): void {
  let x00 = s[0], x01 = s[1], x02 = s[2], x03 = s[3],
      x04 = k[0], x05 = k[1], x06 = k[2], x07 = k[3],
      x08 = k[4], x09 = k[5], x10 = k[6], x11 = k[7],
      x12 = i[0], x13 = i[1], x14 = i[2], x15 = i[3]

  for (let r = 0; r < 20; r += 2) {
    x00 = (x00 + x04) | 0; x12 = rotl(x12 ^ x00, 16)
    x08 = (x08 + x12) | 0; x04 = rotl(x04 ^ x08, 12)
    x00 = (x00 + x04) | 0; x12 = rotl(x12 ^ x00, 8)
    x08 = (x08 + x12) | 0; x04 = rotl(x04 ^ x08, 7)

    x01 = (x01 + x05) | 0; x13 = rotl(x13 ^ x01, 16)
    x09 = (x09 + x13) | 0; x05 = rotl(x05 ^ x09, 12)
    x01 = (x01 + x05) | 0; x13 = rotl(x13 ^ x01, 8)
    x09 = (x09 + x13) | 0; x05 = rotl(x05 ^ x09, 7)

    x02 = (x02 + x06) | 0; x14 = rotl(x14 ^ x02, 16)
    x10 = (x10 + x14) | 0; x06 = rotl(x06 ^ x10, 12)
    x02 = (x02 + x06) | 0; x14 = rotl(x14 ^ x02, 8)
    x10 = (x10 + x14) | 0; x06 = rotl(x06 ^ x10, 7)

    x03 = (x03 + x07) | 0; x15 = rotl(x15 ^ x03, 16)
    x11 = (x11 + x15) | 0; x07 = rotl(x07 ^ x11, 12)
    x03 = (x03 + x07) | 0; x15 = rotl(x15 ^ x03, 8)
    x11 = (x11 + x15) | 0; x07 = rotl(x07 ^ x11, 7)

    x00 = (x00 + x05) | 0; x15 = rotl(x15 ^ x00, 16)
    x10 = (x10 + x15) | 0; x05 = rotl(x05 ^ x10, 12)
    x00 = (x00 + x05) | 0; x15 = rotl(x15 ^ x00, 8)
    x10 = (x10 + x15) | 0; x05 = rotl(x05 ^ x10, 7)

    x01 = (x01 + x06) | 0; x12 = rotl(x12 ^ x01, 16)
    x11 = (x11 + x12) | 0; x06 = rotl(x06 ^ x11, 12)
    x01 = (x01 + x06) | 0; x12 = rotl(x12 ^ x01, 8)
    x11 = (x11 + x12) | 0; x06 = rotl(x06 ^ x11, 7)

    x02 = (x02 + x07) | 0; x13 = rotl(x13 ^ x02, 16)
    x08 = (x08 + x13) | 0; x07 = rotl(x07 ^ x08, 12)
    x02 = (x02 + x07) | 0; x13 = rotl(x13 ^ x02, 8)
    x08 = (x08 + x13) | 0; x07 = rotl(x07 ^ x08, 7)

    x03 = (x03 + x04) | 0; x14 = rotl(x14 ^ x03, 16)
    x09 = (x09 + x14) | 0; x04 = rotl(x04 ^ x09, 12)
    x03 = (x03 + x04) | 0; x14 = rotl(x14 ^ x03, 8)
    x09 = (x09 + x14) | 0; x04 = rotl(x04 ^ x09, 7)
  }

  let oi = 0
  out[oi++] = x00; out[oi++] = x01
  out[oi++] = x02; out[oi++] = x03
  out[oi++] = x12; out[oi++] = x13
  out[oi++] = x14; out[oi++] = x15
}
