/**
 * @module ghash
 * Implementación independiente de GHASH para AES-GCM.
 *
 * Utiliza tablas precomputadas adaptativas (4-bit o 8-bit window) según la longitud.
 * Optimizado para rendimiento en V8.
 */

import { abytes, u32, createView, copyBytes, clean } from "./utils"
import { BLOCK_SIZE, BLOCK_SIZE32 } from "./constants"

const POLY = 0xe1 // Polinomio irreducible de GHASH: x^128 + x^7 + x^2 + x + 1
const ZEROS32 = new Uint32Array(4)

// ─── Utilidades GF(2^128) ───────────────────────────────────────────────────

/** Multiplicación por 2 en GF(2^128) (para GHASH). */
function mul2(s0: number, s1: number, s2: number, s3: number): { s0: number; s1: number; s2: number; s3: number } {
  const hiBit = s3 & 1
  return {
    s3: (s2 << 31) | (s3 >>> 1),
    s2: (s1 << 31) | (s2 >>> 1),
    s1: (s0 << 31) | (s1 >>> 1),
    s0: (s0 >>> 1) ^ ((POLY << 24) & -(hiBit & 1))
  }
}

/** Invierte el endianness de un entero de 32 bits. */
function swapLE(n: number): number {
  return (((n >>> 0) & 0xff) << 24) | (((n >>> 8) & 0xff) << 16) | (((n >>> 16) & 0xff) << 8) | ((n >>> 24) & 0xff)
}

/** Estado interno de bloque. */
type Value = { s0: number; s1: number; s2: number; s3: number }

/** Selecciona el tamaño de ventana óptimo (en bits) según la longitud esperada. */
function estimateWindow(bytes: number): number {
  if (bytes > 64 * 1024) return 8
  if (bytes > 1024) return 4
  return 2
}

// ─── Clase GHASH ─────────────────────────────────────────────────────────────

export class GHASH {
  protected s0 = 0
  protected s1 = 0
  protected s2 = 0
  protected s3 = 0
  protected t: Value[]
  private W: number
  private windowSize: number

  /**
   * Inicializa GHASH con la subclave Hash (H).
   * @param key Subclave H de 16 bytes (E_K(0^128))
   * @param expectedLength Longitud estimada de los datos para optimizar tablas
   */
  constructor(key: Uint8Array, expectedLength: number = 1024) {
    abytes(key, BLOCK_SIZE, "ghash key")
    const kView = createView(key)
    let k0 = kView.getUint32(0, false)
    let k1 = kView.getUint32(4, false)
    let k2 = kView.getUint32(8, false)
    let k3 = kView.getUint32(12, false)

    // Tabla de potencias
    const doubles: Value[] = []
    for (let i = 0; i < 128; i++) {
      doubles.push({ s0: swapLE(k0), s1: swapLE(k1), s2: swapLE(k2), s3: swapLE(k3) })
      ;({ s0: k0, s1: k1, s2: k2, s3: k3 } = mul2(k0, k1, k2, k3))
    }

    const W = estimateWindow(expectedLength)
    this.W = W
    const windows = 128 / W
    const windowSize = (this.windowSize = 2 ** W)
    const items: Value[] = []

    // Precomputar tabla
    for (let w = 0; w < windows; w++) {
      for (let byte = 0; byte < windowSize; byte++) {
        let s0 = 0,
          s1 = 0,
          s2 = 0,
          s3 = 0
        for (let j = 0; j < W; j++) {
          const bit = (byte >>> (W - j - 1)) & 1
          if (!bit) continue
          const { s0: d0, s1: d1, s2: d2, s3: d3 } = doubles[W * w + j]
          s0 ^= d0
          s1 ^= d1
          s2 ^= d2
          s3 ^= d3
        }
        items.push({ s0, s1, s2, s3 })
      }
    }
    this.t = items
  }

  /** Procesa un bloque interno. */
  protected _updateBlock(s0: number, s1: number, s2: number, s3: number): void {
    s0 ^= this.s0
    s1 ^= this.s1
    s2 ^= this.s2
    s3 ^= this.s3
    const { W, t, windowSize } = this
    let o0 = 0,
      o1 = 0,
      o2 = 0,
      o3 = 0
    const mask = (1 << W) - 1
    let w = 0

    const block = [s0, s1, s2, s3]
    for (let i = 0; i < 4; i++) {
      const num = block[i]
      for (let bytePos = 0; bytePos < 4; bytePos++) {
        const byte = (num >>> (8 * bytePos)) & 0xff
        for (let bitPos = 8 / W - 1; bitPos >= 0; bitPos--) {
          const bit = (byte >>> (W * bitPos)) & mask
          const { s0: e0, s1: e1, s2: e2, s3: e3 } = t[w * windowSize + bit]
          o0 ^= e0
          o1 ^= e1
          o2 ^= e2
          o3 ^= e3
          w += 1
        }
      }
    }
    this.s0 = o0
    this.s1 = o1
    this.s2 = o2
    this.s3 = o3
  }

  /** Procesa datos (debe ser múltiplo de 16 bytes o el bloque final rellenado con ceros). */
  update(data: Uint8Array): this {
    abytes(data)
    const b32 = u32(data)
    const blocks = Math.floor(data.length / BLOCK_SIZE)
    const left = data.length % BLOCK_SIZE

    // Bloques completos
    for (let i = 0; i < blocks; i++) {
      this._updateBlock(b32[i * 4 + 0], b32[i * 4 + 1], b32[i * 4 + 2], b32[i * 4 + 3])
    }

    // Datos sobrantes (incompleto) -> rellenar con ceros implícitamente
    if (left > 0) {
      const pad = new Uint8Array(BLOCK_SIZE)
      pad.set(data.subarray(blocks * BLOCK_SIZE))
      const pad32 = u32(pad)
      this._updateBlock(pad32[0], pad32[1], pad32[2], pad32[3])
    }

    return this
  }

  /**
   * Retorna el bloque de autenticación GHash y limpia memoria interna.
   */
  digestInto(out: Uint8Array): void {
    const o32 = u32(out)
    o32[0] = this.s0
    o32[1] = this.s1
    o32[2] = this.s2
    o32[3] = this.s3
  }

  digest(): Uint8Array {
    const res = new Uint8Array(BLOCK_SIZE)
    this.digestInto(res)
    return res
  }

  /** Destruye datos sensibles (claves precomputadas). */
  destroy(): void {
    this.s0 = this.s1 = this.s2 = this.s3 = 0
    for (const elm of this.t) {
      elm.s0 = elm.s1 = elm.s2 = elm.s3 = 0
    }
  }
}
