// Calculadora WebSocket - Servidor Node.js
// Implementa el protocolo RFC 6455 a mano (sin librerías) para evidenciar
// cada fase descrita en el documento: handshake, frames, enmascarado y cierre.

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 8080;
const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"; // GUID fijo del RFC 6455

const OPCODES = { TEXT: 0x1, BINARY: 0x2, CLOSE: 0x8, PING: 0x9, PONG: 0xa };

// ---------------------------------------------------------------------------
// Servidor HTTP: entrega la interfaz del cliente (index.html)
// ---------------------------------------------------------------------------
const server = http.createServer((req, res) => {
  if (req.url === "/" || req.url === "/index.html") {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    fs.createReadStream(path.join(__dirname, "public", "index.html")).pipe(res);
    return;
  }
  res.writeHead(404);
  res.end("No encontrado");
});

// ---------------------------------------------------------------------------
// Fase 1: Handshake (HTTP Upgrade -> 101 Switching Protocols)
// ---------------------------------------------------------------------------
server.on("upgrade", (req, socket) => {
  const key = req.headers["sec-websocket-key"];
  const version = req.headers["sec-websocket-version"];

  if (req.url !== "/ws" || (req.headers.upgrade || "").toLowerCase() !== "websocket" || !key || version !== "13") {
    socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
    return;
  }

  // Sec-WebSocket-Accept = Base64( SHA-1( Key + GUID ) )
  const accept = crypto.createHash("sha1").update(key + GUID).digest("base64");

  socket.write(
    "HTTP/1.1 101 Switching Protocols\r\n" +
      "Upgrade: websocket\r\n" +
      "Connection: Upgrade\r\n" +
      `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
  );

  const id = `${socket.remoteAddress}:${socket.remotePort}`;
  log(id, "HANDSHAKE", `GET ${req.url} Upgrade: websocket`);
  log(id, "HANDSHAKE", `Sec-WebSocket-Key:    ${key}`);
  log(id, "HANDSHAKE", `Sec-WebSocket-Accept: ${accept}`);
  log(id, "HANDSHAKE", "101 Switching Protocols -> conexión WebSocket activa");

  handleConnection(socket, id);
});

// ---------------------------------------------------------------------------
// Fase 2: Transferencia de datos (lectura de frames)
// ---------------------------------------------------------------------------
function handleConnection(socket, id) {
  let buffer = Buffer.alloc(0);
  let closing = false;

  socket.on("data", (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);

    // Un "data" de TCP puede traer varios frames o un frame incompleto
    let frame;
    while ((frame = parseFrame(buffer))) {
      buffer = buffer.subarray(frame.length);
      onFrame(frame);
    }
  });

  socket.on("close", () => log(id, "TCP", "Socket cerrado"));
  socket.on("error", (err) => log(id, "ERROR", err.message));

  function onFrame(frame) {
    log(
      id,
      "FRAME <-",
      `FIN=${frame.fin} opcode=0x${frame.opcode.toString(16)} MASK=${frame.masked} ` +
        `len=${frame.payload.length} maskKey=${frame.maskKey ? frame.maskKey.toString("hex") : "-"}`
    );

    // RFC 6455: todo frame cliente -> servidor DEBE venir enmascarado
    if (!frame.masked) {
      sendClose(1002, "Frame del cliente sin mascara");
      return;
    }

    switch (frame.opcode) {
      case OPCODES.TEXT:
        handleCalculation(frame.payload.toString("utf8"));
        break;
      case OPCODES.PING:
        sendFrame(socket, OPCODES.PONG, frame.payload);
        log(id, "FRAME ->", "PONG");
        break;
      case OPCODES.CLOSE:
        handleClose(frame.payload);
        break;
      default:
        sendClose(1003, "Tipo de dato no soportado");
    }
  }

  // -------------------------------------------------------------------------
  // Procesamiento: unmarshaling del JSON + operación aritmética
  // -------------------------------------------------------------------------
  function handleCalculation(text) {
    log(id, "PAYLOAD", `JSON recibido (ya desenmascarado): ${text}`);

    let response;
    try {
      const { operacion, a, b } = JSON.parse(text);
      const resultado = calcular(operacion, Number(a), Number(b));
      response = { resultado, status: "ok" };
      log(id, "CALCULO", `${a} ${simbolo(operacion)} ${b} = ${resultado}`);
    } catch (err) {
      response = { status: "error", mensaje: err.message };
      log(id, "CALCULO", `Error: ${err.message}`);
    }

    const json = JSON.stringify(response);
    sendFrame(socket, OPCODES.TEXT, Buffer.from(json, "utf8"));
    log(id, "FRAME ->", `opcode=0x1 MASK=0 payload=${json}`);
  }

  // -------------------------------------------------------------------------
  // Fase 3: Cierre (close frame 0x8 + confirmación)
  // -------------------------------------------------------------------------
  function handleClose(payload) {
    const code = payload.length >= 2 ? payload.readUInt16BE(0) : 1005;
    const reason = payload.length > 2 ? payload.subarray(2).toString("utf8") : "";
    log(id, "CLOSE", `Cliente solicita cierre: código ${code} ${reason}`);

    if (!closing) {
      // Confirmamos con otro close frame y cerramos el TCP
      sendClose(code === 1005 ? 1000 : code, "Cierre confirmado");
    }
    socket.end();
  }

  function sendClose(code, reason) {
    closing = true;
    const payload = Buffer.alloc(2 + Buffer.byteLength(reason));
    payload.writeUInt16BE(code, 0);
    payload.write(reason, 2);
    sendFrame(socket, OPCODES.CLOSE, payload);
    log(id, "FRAME ->", `CLOSE código ${code} (${reason})`);
  }
}

// ---------------------------------------------------------------------------
// Lectura de un frame: cabecera de 2 a 14 bytes + payload
// Devuelve null si el buffer todavía no contiene el frame completo.
// ---------------------------------------------------------------------------
function parseFrame(buf) {
  if (buf.length < 2) return null;

  const fin = (buf[0] & 0x80) !== 0;
  const opcode = buf[0] & 0x0f;
  const masked = (buf[1] & 0x80) !== 0;
  let payloadLength = buf[1] & 0x7f;
  let offset = 2;

  // Payload length de 7, 7+16 o 7+64 bits
  if (payloadLength === 126) {
    if (buf.length < offset + 2) return null;
    payloadLength = buf.readUInt16BE(offset);
    offset += 2;
  } else if (payloadLength === 127) {
    if (buf.length < offset + 8) return null;
    payloadLength = Number(buf.readBigUInt64BE(offset));
    offset += 8;
  }

  let maskKey = null;
  if (masked) {
    if (buf.length < offset + 4) return null;
    maskKey = buf.subarray(offset, offset + 4);
    offset += 4;
  }

  if (buf.length < offset + payloadLength) return null;

  // Desenmascarado XOR: byte[i] ^ maskKey[i % 4]
  const payload = Buffer.from(buf.subarray(offset, offset + payloadLength));
  if (masked) {
    for (let i = 0; i < payload.length; i++) payload[i] ^= maskKey[i % 4];
  }

  return { fin, opcode, masked, maskKey, payload, length: offset + payloadLength };
}

// ---------------------------------------------------------------------------
// Escritura de un frame servidor -> cliente (FIN=1, MASK=0)
// ---------------------------------------------------------------------------
function sendFrame(socket, opcode, payload) {
  let header;
  if (payload.length < 126) {
    header = Buffer.alloc(2);
    header[1] = payload.length;
  } else if (payload.length < 65536) {
    header = Buffer.alloc(4);
    header[1] = 126;
    header.writeUInt16BE(payload.length, 2);
  } else {
    header = Buffer.alloc(10);
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(payload.length), 2);
  }
  header[0] = 0x80 | opcode; // FIN=1 + opcode
  socket.write(Buffer.concat([header, payload]));
}

// ---------------------------------------------------------------------------
// Lógica de la calculadora
// ---------------------------------------------------------------------------
function calcular(operacion, a, b) {
  if (Number.isNaN(a) || Number.isNaN(b)) throw new Error("Los operandos deben ser números");
  switch (operacion) {
    case "sumar":
      return a + b;
    case "restar":
      return a - b;
    case "multiplicar":
      return a * b;
    case "dividir":
      if (b === 0) throw new Error("División para cero");
      return a / b;
    default:
      throw new Error(`Operación desconocida: ${operacion}`);
  }
}

function simbolo(operacion) {
  return { sumar: "+", restar: "-", multiplicar: "×", dividir: "÷" }[operacion] || "?";
}

function log(id, fase, mensaje) {
  const hora = new Date().toLocaleTimeString();
  console.log(`[${hora}] [${id}] ${fase.padEnd(9)} ${mensaje}`);
}

server.listen(PORT, () => {
  console.log(`Calculadora WebSocket escuchando en http://localhost:${PORT}`);
  console.log(`Endpoint WebSocket: ws://localhost:${PORT}/ws`);
});
