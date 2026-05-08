/**
 * @module utils
 * Utilidades para manipulación de bytes, hex y validación.
 * Funciones puras, sin dependencias externas.
 */

// ─── Tipos ───────────────────────────────────────────────────────────────────

/** Tipos de arrays tipados soportados (8/16/32-bit). */
export type TypedArray =
  | Int8Array
  | Uint8ClampedArray
  | Uint8Array
  | Uint16Array
  | Int16Array
  | Uint32Array
  | Int32Array

/** Interfaz de cifrador síncrono. */
export type Cipher = {
  encrypt(plaintext: Uint8Array): Uint8Array
  decrypt(ciphertext: Uint8Array): Uint8Array
}

/** Cifrador con soporte para buffer de salida pre-asignado. */
export type CipherWithOutput = Cipher & {
  encrypt(plaintext: Uint8Array, output?: Uint8Array): Uint8Array
  decrypt(ciphertext: Uint8Array, output?: Uint8Array): Uint8Array
}

/** Opciones de bloque (ECB/CBC). */
export type BlockOpts = { disablePadding?: boolean }

/** Parámetros del cifrador (adjuntos al constructor). */
export type CipherParams = {
  blockSize: number
  nonceLength?: number
  tagLength?: number
  varSizeNonce?: boolean
}

/** Constructor genérico de cifradores. */
export type CipherCons<T extends any[]> = (key: Uint8Array, ...args: T) => Cipher

// ─── Detección de plataforma ─────────────────────────────────────────────────

/** ¿La plataforma actual es little-endian? */
export const isLE: boolean = new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44

// ─── Validaciones ────────────────────────────────────────────────────────────

/** Verifica que el valor sea un Uint8Array, opcionalmente con longitud exacta. */
export function abytes(value: Uint8Array, length?: number, title: string = ""): Uint8Array {
  const valid = value instanceof Uint8Array
  const len = value?.length
  const needsLen = length !== undefined
  if (!valid || (needsLen && len !== length)) {
    const prefix = title && `"${title}" `
    const ofLen = needsLen ? ` of length ${length}` : ""
    const got = valid ? `length=${len}` : `type=${typeof value}`
    throw new Error(prefix + "expected Uint8Array" + ofLen + ", got " + got)
  }
  return value
}

// ─── Conversión de tipos ─────────────────────────────────────────────────────

/** Reinterpreta un TypedArray como Uint8Array (misma memoria). */
export function u8(arr: TypedArray): Uint8Array {
  return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength)
}

/** Reinterpreta un TypedArray como Uint32Array (misma memoria). */
export function u32(arr: TypedArray): Uint32Array {
  return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4))
}

/** Crea un DataView sobre un TypedArray. */
export function createView(arr: TypedArray): DataView {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength)
}

// ─── Operaciones con bytes ───────────────────────────────────────────────────

/** Zeroiza arrays (limpieza de memoria sensible). */
export function clean(...arrays: TypedArray[]): void {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0)
  }
}

/** Verifica si un Uint8Array está alineado a 4 bytes (u32). */
export function isAligned32(bytes: Uint8Array): boolean {
  return bytes.byteOffset % 4 === 0
}

/** Copia bytes a un nuevo Uint8Array alineado. */
export function copyBytes(bytes: Uint8Array): Uint8Array {
  return Uint8Array.from(bytes)
}

/** Concatena múltiples Uint8Array en uno solo. */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let sum = 0
  for (let i = 0; i < arrays.length; i++) {
    abytes(arrays[i])
    sum += arrays[i].length
  }
  const res = new Uint8Array(sum)
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    res.set(arrays[i], pad)
    pad += arrays[i].length
  }
  return res
}

/**
 * Verifica si dos Uint8Array comparten el mismo buffer y se solapan.
 * El solapamiento puede corromper datos durante operaciones in-place.
 */
export function overlapBytes(a: Uint8Array, b: Uint8Array): boolean {
  return (
    a.buffer === b.buffer && a.byteOffset < b.byteOffset + b.byteLength && b.byteOffset < a.byteOffset + a.byteLength
  )
}

/**
 * Lanza error si input y output se solapan de forma compleja
 * (input empieza antes que output en el mismo buffer).
 */
export function complexOverlapBytes(input: Uint8Array, output: Uint8Array): void {
  if (overlapBytes(input, output) && input.byteOffset < output.byteOffset)
    throw new Error("solapamiento complejo de input y output no soportado")
}

/**
 * Retorna un buffer de salida. Si `out` es undefined, crea uno nuevo.
 * Si `out` está definido, valida longitud y alineación.
 */
export function getOutput(expectedLength: number, out?: Uint8Array, onlyAligned = true): Uint8Array {
  if (out === undefined) return new Uint8Array(expectedLength)
  if (out.length !== expectedLength)
    throw new Error('"output" expected Uint8Array of length ' + expectedLength + ", got: " + out.length)
  if (onlyAligned && !isAligned32(out)) throw new Error("output inválido, debe estar alineado")
  return out
}

/** Compara 2 Uint8Array en tiempo semi-constante. */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

// ─── Hex ─────────────────────────────────────────────────────────────────────

const hexes = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"))

/** Convierte Uint8Array a string hexadecimal. */
export function bytesToHex(bytes: Uint8Array): string {
  abytes(bytes)
  let hex = ""
  for (let i = 0; i < bytes.length; i++) hex += hexes[bytes[i]]
  return hex
}

const asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 } as const

function asciiToBase16(ch: number): number | undefined {
  if (ch >= asciis._0 && ch <= asciis._9) return ch - asciis._0
  if (ch >= asciis.A && ch <= asciis.F) return ch - (asciis.A - 10)
  if (ch >= asciis.a && ch <= asciis.f) return ch - (asciis.a - 10)
  return
}

/** Convierte string hexadecimal a Uint8Array. */
export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== "string") throw new Error("se esperaba un string hex, se obtuvo " + typeof hex)
  const hl = hex.length
  const al = hl / 2
  if (hl % 2) throw new Error("se esperaba hex string par, longitud impar: " + hl)
  const array = new Uint8Array(al)
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    const n1 = asciiToBase16(hex.charCodeAt(hi))
    const n2 = asciiToBase16(hex.charCodeAt(hi + 1))
    if (n1 === undefined || n2 === undefined) {
      const char = hex[hi] + hex[hi + 1]
      throw new Error('carácter no-hex "' + char + '" en posición ' + hi)
    }
    array[ai] = n1 * 16 + n2
  }
  return array
}

// ─── wrapCipher ──────────────────────────────────────────────────────────────

/**
 * Envuelve un constructor de cifrador con validaciones:
 * - Valida key, nonce, AAD
 * - Asegura que encrypt() solo se llame una vez (misma key + nonce)
 * - Adjunta los parámetros (blockSize, nonceLength, etc.) al constructor
 */
export const wrapCipher = <C extends CipherCons<any>, P extends CipherParams>(params: P, constructor: C): C & P => {
  function wrappedCipher(key: Uint8Array, ...args: any[]): CipherWithOutput {
    abytes(key, undefined, "key")
    if (!isLE) throw new Error("hardware no little-endian no soportado aún")
    if (params.nonceLength !== undefined) {
      abytes(args[0], params.varSizeNonce ? undefined : params.nonceLength, "nonce/iv")
    }
    const cipher = constructor(key, ...args)
    let called = false
    return {
      encrypt(data: Uint8Array, output?: Uint8Array) {
        if (called) throw new Error("no se puede encrypt() dos veces con la misma key + nonce")
        called = true
        abytes(data)
        return (cipher as CipherWithOutput).encrypt(data, output)
      },
      decrypt(data: Uint8Array, output?: Uint8Array) {
        abytes(data)
        return (cipher as CipherWithOutput).decrypt(data, output)
      }
    }
  }
  Object.assign(wrappedCipher, params)
  return wrappedCipher as C & P
}

// ─── Utilidades para Longitudes de 64 bits (GCM) ─────────────────────────────

/**
 * Serializa longitudes binarias en bloques de 64 bits para GCM (AAD y Data).
 */
export function u64Lengths(dataLength: number, aadLength: number, isLE: boolean): Uint8Array {
  const num = new Uint8Array(16)
  const view = createView(num)
  view.setBigUint64(0, BigInt(aadLength), isLE)
  view.setBigUint64(8, BigInt(dataLength), isLE)
  return num
}

// ─── BigInt ──────────────────────────────────────────────────────────────────

/** Convierte Uint8Array (big-endian) a BigInt. */
export function bytesToNumberBE(bytes: Uint8Array): bigint {
  let res = 0n
  for (let i = 0; i < bytes.length; i++) res = (res << 8n) | BigInt(bytes[i])
  return res
}

/** Convierte BigInt a Uint8Array (big-endian) de longitud fija. */
export function numberToBytesBE(n: bigint, len: number): Uint8Array {
  const res = new Uint8Array(len)
  for (let i = len - 1; i >= 0; i--) {
    res[i] = Number(n & 0xffn)
    n >>= 8n
  }
  return res
}
