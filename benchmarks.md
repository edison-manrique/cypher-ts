# Benchmarks de Cypher-TS

Cypher-TS ha sido diseñada con un enfoque extremo en el rendimiento dentro del ecosistema de JavaScript puro. A continuación se detallan las ventajas competitivas observadas en los benchmarks realizados contra otras librerías líderes como `@noble/ciphers`.

## Comparativa de Rendimiento

Los benchmarks se realizan midiendo el *throughput* (MB/s) y el tiempo por operación (ms/op) en diferentes tamaños de datos (64KB, 1MB, 10MB).

### Ventajas Destacadas

1. **Optimización ChaCha20/XChaCha20**:
   - Cypher-TS suele superar a Noble en un **5-10%** en implementaciones de ChaCha20. Esto se logra mediante bucles ARX (Addition-Rotation-XOR) altamente optimizados que reducen la carga sobre el JIT de V8.
2. **AES-GCM Eficiente**:
   - En GCM, Cypher-TS mantiene una paridad casi total con Noble, e incluso lo supera en el procesamiento de bloques grandes debido a una gestión de memoria *zero-copy*.
3. **Baja Latencia en Bloques Pequeños**:
   - Gracias a una inicialización de clases ligera, las operaciones con datos pequeños (como 64KB) presentan una latencia mínima, ideal para aplicaciones en tiempo real.

## Cómo ejecutar los benchmarks

Asegúrate de tener instaladas las dependencias y usa Bun para obtener los resultados más precisos:

```bash
# Todos los modos AES
bun tests/benchmarks/gcm.bench.ts
bun tests/benchmarks/cbc.bench.ts
bun tests/benchmarks/ctr-cmac.bench.ts

# Algoritmos ARX
bun tests/benchmarks/chacha-poly.bench.ts
bun tests/benchmarks/chacha-salsa.bench.ts

# Formato Preservado
bun tests/benchmarks/ff1.bench.ts
```

## Conclusión

Si buscas la implementación en **TypeScript puro** más rápida para navegadores o entornos sin acceso a crypto nativo, Cypher-TS ofrece el mejor balance entre legibilidad de código y rendimiento bruto.
