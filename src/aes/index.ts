/**
 * @module index
 * Punto de entrada de la biblioteca AES-TS.
 * Exporta todos los modos de cifrado y utilidades disponibles.
 */

// Modos
export { CBC } from "./cbc"
export { GCM } from "./gcm"
export { CTR } from "./ctr"
export { CMAC } from "./cmac"
export { FF1, BinaryFF1 } from "./ff1"

// Utilidades públicas
export { hexToBytes, bytesToHex, concatBytes, equalBytes } from "./utils"

// Tipos
export type { Cipher, CipherWithOutput, BlockOpts } from "./utils"
