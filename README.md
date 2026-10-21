# Calculadora WebSocket

Ejemplo práctico del trabajo **"Análisis y ejemplo conceptual de un sistema de comunicación distribuido"** — Sistemas Distribuidos, UDLA (Quito, 2026).

El servidor implementa el protocolo **WebSocket (RFC 6455) a mano, sin librerías**, para evidenciar cada fase de la comunicación:

1. **Handshake** — `HTTP GET Upgrade: websocket` → `101 Switching Protocols`, calculando `Sec-WebSocket-Accept = Base64(SHA-1(Key + GUID))`.
2. **Transferencia de datos** — lectura de frames (FIN, opcode, MASK, longitud, masking key), desenmascarado XOR del payload y respuesta con frame de texto `0x1` sin máscara.
3. **Cierre** — intercambio de close frames (opcode `0x8`) y cierre limpio del socket TCP.

## Estructura del mensaje

Cliente → Servidor:
```json
{ "operacion": "sumar", "a": 15, "b": 27 }
```

Servidor → Cliente:
```json
{ "resultado": 42, "status": "ok" }
```

Operaciones soportadas: `sumar`, `restar`, `multiplicar`, `dividir`.

## Ejecución

Requiere Node.js 18 o superior.

```bash
npm start
```

Abrir http://localhost:8080, pulsar **Conectar**, ingresar los números y pulsar **Calcular**.
La consola del servidor muestra cada fase del protocolo (handshake, frames recibidos/enviados, cálculo y cierre).

## Integrantes

Miguel Peña, Carlos Carvajal, Mateo Enriquez, Sthefano Zambrano

Profesor: Hugo Chimbo Acosta
