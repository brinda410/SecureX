import "dotenv/config";
import Redis from "ioredis";

const redisUrl = process.env.REDIS_URL?.trim();

if (!redisUrl) {
    console.error("REDIS_URL is missing.");
    process.exit(1);
}

let url;

try {
    url = new URL(redisUrl);
} catch {
    console.error("Invalid REDIS_URL format.");
    process.exit(1);
}

const redis = new Redis({
    host: url.hostname,
    port: Number(url.port),

    username: decodeURIComponent(url.username || "default"),
    password: decodeURIComponent(url.password),

    // Explicit TLS, matching Upstash's --tls command.
    tls: {
        servername: url.hostname,
        rejectUnauthorized: true
    },

    lazyConnect: true,
    enableReadyCheck: false,
    connectTimeout: 15000,
    maxRetriesPerRequest: 1,

    retryStrategy: () => null
});

redis.on("connect", () => {
    console.log("TCP connection established.");
});

redis.on("ready", () => {
    console.log("Redis is ready.");
});

redis.on("error", (error) => {
    console.error("Redis error:", error.message);
});

redis.on("close", () => {
    console.log("Redis connection closed.");
});

async function testRedis() {
    try {
        console.log("Testing Upstash Redis with explicit TLS...");

        await redis.connect();

        const response = await redis.ping();

        console.log("PING RESPONSE:", response);

        if (response === "PONG") {
            console.log("SUCCESS: Redis authentication and connection work!");
        }

    } catch (error) {
        console.error("TEST FAILED:", error.message);

    } finally {
        redis.disconnect();
    }
}

testRedis();
