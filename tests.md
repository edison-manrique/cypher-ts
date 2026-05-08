# Pruebas Unitarias y Vectores de Prueba

La robustez de Cypher-TS se garantiza mediante una suite exhaustiva de pruebas unitarias que verifican la corrección algorítmica contra vectores de prueba oficiales (NIST, RFC).

## Cobertura de Pruebas

Actualmente, la suite incluye validaciones para:

- **AES-CBC / GCM / CTR**: Verificado contra vectores del NIST.
- **ChaCha20 / XChaCha20**: Validado según el RFC 8439.
- **Poly1305**: Pruebas de integridad MAC.
- **FF1**: Pruebas con diferentes radix (10, 36) y longitudes de tweak.

## Cómo ejecutar las pruebas

Para asegurar que todo funciona correctamente después de realizar cambios:

```bash
# Ejecutar todas las pruebas con Bun
bun test tests/*.test.ts
```

## Estructura de Tests

- `tests/vectors/`: Contiene archivos JSON con los vectores de prueba oficiales.
- `tests/*.test.ts`: Implementaciones de las pruebas usando los vectores.

## Garantía de Calidad

Cada operación de cifrado y descifrado se prueba cruzando resultados entre diferentes implementaciones para asegurar que no existan regresiones en la lógica de bloques o el manejo de padding.
