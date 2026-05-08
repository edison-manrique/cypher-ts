# Cypher-TS

Biblioteca de criptografía de alto rendimiento en TypeScript puro, enfocada en algoritmos modernos (AEAD) y modos clásicos. Diseñada para entornos de Navegador y Servidor (Bun/Node) con cero dependencias y un enfoque en la velocidad.

## Características

- **Modos AES**:
  - GCM (Galois/Counter Mode) - AEAD de alto rendimiento.
  - CBC (Cipher Block Chaining).
  - CTR (Counter Mode).
  - CMAC (Cipher-based Message Authentication Code).
  - FF1 (Format-Preserving Encryption).
- **Cifradores de Flujo (ARX)**:
  - ChaCha20 y XChaCha20 (RFC 8439).
  - Salsa20 y XSalsa20.
- **MACs**:
  - Poly1305.
- **Rendimiento**: Primitivas ARX optimizadas y gestión de buffers sin copias innecesarias (zero-copy).
- **Entorno**: Compatible con Bun, Node.js y navegadores modernos.

## Instalación

```bash
npm install cypher-ts
# o
bun add cypher-ts
```

## Uso

### AES-GCM (Cifrado Autenticado)

```typescript
import { GCM } from 'cypher-ts';

const key = new Uint8Array(32); // Clave de 256 bits
const nonce = new Uint8Array(12); // Nonce de 96 bits
const data = new TextEncoder().encode("Mensaje secreto");

const cipher = new GCM(key, nonce);
const encrypted = cipher.encrypt(data); // Retorna [ciphertext + tag de 16 bytes]
const decrypted = cipher.decrypt(encrypted);
```

### ChaCha20-Poly1305

```typescript
import { ChaCha20Poly1305 } from 'cypher-ts';

const aead = new ChaCha20Poly1305(key, nonce);
const ciphertext = aead.encrypt(data);
const plaintext = aead.decrypt(ciphertext);
```

### Cifrado Preservador de Formato (FF1)

```typescript
import { FF1 } from 'cypher-ts';

const ff1 = new FF1(10, key, tweak); // Radix 10 (dígitos)
const dígitos = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0];
const encrypted = ff1.encrypt(dígitos);
```

## Benchmarks

Esta biblioteca ha sido diseñada para ser una de las implementaciones en JavaScript puro más rápidas existentes, superando o igualando a menudo a `@noble/ciphers` en algoritmos como ChaCha20 y GCM.

Para ejecutar los benchmarks:
```bash
bun run bench
# o ejecutar uno específico
bun tests/benchmarks/gcm.bench.ts
```

## Seguridad

Esta es una implementación en TypeScript puro. Aunque utiliza operaciones de tiempo constante para ARX (ChaCha/Salsa), los motores de JavaScript pueden introducir canales laterales de tiempo a través de optimizaciones JIT. Para requisitos de alta seguridad en Node/Bun, considere el uso de bindings nativos si están disponibles.

## Licencia

MIT
