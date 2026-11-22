import "dotenv/config";
import tls from "tls";

const redisUrl = process.env.REDIS_URL?.trim();

if (!redisUrl) {
    console.error("REDIS_URL is missing.");
    process.exit(1);
}

const url = new URL(redisUrl);

console.log("Testing TLS connection...");
console.log("Host:", url.hostname);
console.log("Port:", url.port);

const socket = tls.connect({
    host: url.hostname,
    port: Number(url.port),
    servername: url.hostname,
    rejectUnauthorized: true,
    timeout: 15000
});

socket.on("secureConnect", () => {
    console.log("SUCCESS: TLS handshake completed.");
    console.log("TLS version:", socket.getProtocol());
    socket.end();
});

socket.on("error", (error) => {
    console.error("TLS ERROR:", error.message);
});

socket.on("timeout", () => {
    console.error("TLS connection timed out.");
    socket.destroy();
});
