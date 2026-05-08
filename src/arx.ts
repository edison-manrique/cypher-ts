/**
 * @module arx
 * Utilidades compartidas para cifrados ARX (Add-Rotate-XOR).
 *
 * Base para ChaCha y Salsa: manejo de sigma, claves, nonces y ejecución
 * del cifrador de flujo basado en bloques de 512 bits (64 bytes).
 */

// ─── Constantes ──────────────────────────────────────────────────────────────

/** Bloque de cifrado ARX: 512 bits = 64 bytes = 16 u32. */
export const BLOCK_LEN = 64
export const BLOCK_LEN32 = 16
export const MAX_COUNTER = 2 ** 32 - 1

/** Sigma para claves de 32 bytes: "expand 32-byte k" */
const sigma32 = Uint8Array.from("expand 32-byte k".split(""), (c) => c.charCodeAt(0))
/** Sigma para claves de 16 bytes: "expand 16-byte k" */
const sigma16 = Uint8Array.from("expand 16-byte k".split(""), (c) => c.charCodeAt(0))

export const SIGMA32 = new Uint32Array(sigma32.buffer)
export const SIGMA16 = new Uint32Array(sigma16.buffer)

// ─── Utilidades ──────────────────────────────────────────────────────────────

/** Rotación izquierda de 32 bits. */
export function rotl(a: number, b: number): number {
  return (a << b) | (a >>> (32 - b))
}

/** Convierte Uint8Array a Uint32Array (misma memoria). */
export function u32(bytes: Uint8Array): Uint32Array {
  return new Uint32Array(bytes.buffer, bytes.byteOffset, Math.floor(bytes.byteLength / 4))
}

/** Limpia arrays sensibles. */
export function clean(...arrays: (Uint8Array | Uint32Array)[]): void {
  for (const a of arrays) a.fill(0)
}

/** Valida que sea Uint8Array con longitud opcional. */
export function abytes(data: unknown, len?: number, name = ""): void {
  if (!(data instanceof Uint8Array)) throw new Error(name + " debe ser Uint8Array")
  if (len !== undefined && data.length !== len)
    throw new Error(`${name} se esperaba longitud ${len}, tiene ${data.length}`)
}

/** Copia bytes a un nuevo Uint8Array alineado. */
export function copyBytes(bytes: Uint8Array): Uint8Array {
  return Uint8Array.from(bytes)
}

/** Verifica alineación a 4 bytes. */
export function isAligned32(b: Uint8Array): boolean {
  return b.byteOffset % 4 === 0
}

// ─── Tipo de función core ────────────────────────────────────────────────────

/** Firma de la función core (ChaCha/Salsa). Genera un bloque de 64 bytes. */
export type CoreFn = (
  sigma: Uint32Array,
  key: Uint32Array,
  nonce: Uint32Array,
  output: Uint32Array,
  counter: number,
  rounds: number
) => void

/** Firma de la función hchacha/hsalsa: extiende nonce→key para variantes X. */
export type ExtendNonceFn = (sigma: Uint32Array, key: Uint32Array, input: Uint32Array, output: Uint32Array) => void

// ─── Ejecución del cifrador ──────────────────────────────────────────────────

/**
 * Ejecuta el cifrador de flujo ARX sobre los datos.
 * Para cada bloque, genera keystream con `core()` y XOR con src.
 */
export function runCipher(
  core: CoreFn,
  sigma: Uint32Array,
  key: Uint32Array,
  nonce: Uint32Array,
  data: Uint8Array,
  output: Uint8Array,
  counter: number,
  rounds: number
): void {
  const len = data.length
  const block = new Uint8Array(BLOCK_LEN)
  const b32 = u32(block)
  const aligned = isAligned32(data) && isAligned32(output)
  const d32 = aligned ? u32(data) : undefined
  const o32 = aligned ? u32(output) : undefined

  for (let pos = 0; pos < len; counter++) {
    core(sigma, key, nonce, b32, counter, rounds)
    if (counter >= MAX_COUNTER) throw new Error("arx: desbordamiento del contador")
    const take = Math.min(BLOCK_LEN, len - pos)

    // Ruta rápida: bloques completos alineados
    if (aligned && take === BLOCK_LEN && d32 && o32) {
      const pos32 = pos / 4
      for (let j = 0; j < BLOCK_LEN32; j++) {
        o32[pos32 + j] = d32[pos32 + j] ^ b32[j]
      }
      pos += BLOCK_LEN
      continue
    }

    // Ruta lenta: byte a byte
    for (let j = 0; j < take; j++) {
      output[pos + j] = data[pos + j] ^ block[j]
    }
    pos += take
  }
}

// ─── Preparación de clave ────────────────────────────────────────────────────

/**
 * Prepara clave y sigma según longitud.
 * - 32 bytes → sigma32, key tal cual
 * - 16 bytes → sigma16, key duplicado (key|key)
 */
export function prepareKey(key: Uint8Array, allowShortKeys: boolean): { sigma: Uint32Array; k: Uint8Array } {
  const l = key.length
  if (l === 32) {
    return { sigma: SIGMA32, k: copyBytes(key) }
  } else if (l === 16 && allowShortKeys) {
    const k = new Uint8Array(32)
    k.set(key)
    k.set(key, 16)
    return { sigma: SIGMA16, k }
  }
  throw new Error(`arx: clave debe ser 32 bytes${allowShortKeys ? " o 16 bytes" : ""}, tiene ${l}`)
}
