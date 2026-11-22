import "dotenv/config";
import Redis from "ioredis";

let redisClient = null;
let redisPubClient = null;
let redisSubClient = null;

// ==========================================
// 1. REDIS CONNECTION CONFIGURATION
// ==========================================

function createRedisConnectionOptions() {
    const redisUrl = process.env.REDIS_URL?.trim();

    if (!redisUrl) {
        throw new Error("REDIS_URL is missing from server/.env");
    }

    let parsedUrl;

    try {
        parsedUrl = new URL(redisUrl);
    } catch {
        throw new Error("Invalid REDIS_URL format.");
    }

    if (!["redis:", "rediss:"].includes(parsedUrl.protocol)) {
        throw new Error("Invalid Redis URL protocol.");
    }

    if (
        !parsedUrl.hostname ||
        !parsedUrl.port ||
        !parsedUrl.password
    ) {
        throw new Error("Redis URL is incomplete.");
    }

    const host = parsedUrl.hostname;

    return {
        host,
        port: Number(parsedUrl.port),

        username: decodeURIComponent(
            parsedUrl.username || "default"
        ),

        password: decodeURIComponent(parsedUrl.password),

        tls: {
            servername: host,
            rejectUnauthorized: true
        },

        lazyConnect: true,
        enableReadyCheck: true,
        connectTimeout: 15000,
        maxRetriesPerRequest: 3,

        retryStrategy(times) {
            if (times > 5) return null;

            return Math.min(times * 1000, 5000);
        }
    };
}

// ==========================================
// 2. MAIN REDIS CLIENT
// ==========================================

export const getRedisClient = () => {
    if (redisClient) {
        return redisClient;
    }

    const options = createRedisConnectionOptions();

    console.log("Redis endpoint:", options.host);
    console.log("Redis TLS enabled.");

    redisClient = new Redis(options);

    redisClient.on("connect", () => {
        console.log("Redis main connection established.");
    });

    redisClient.on("ready", () => {
        console.log("Redis main connection ready.");
    });

    redisClient.on("error", (error) => {
        console.error(
            "Redis main connection error:",
            error.message
        );
    });

    redisClient.on("close", () => {
        console.warn("Redis main connection closed.");
    });

    redisClient.on("reconnecting", () => {
        console.log("Redis main reconnecting...");
    });

    return redisClient;
};

// ==========================================
// 3. SOCKET.IO PUBLISHER AND SUBSCRIBER
// ==========================================

export const getRedisPubSubClients = () => {
    if (!redisPubClient || !redisSubClient) {
        throw new Error(
            "Redis Pub/Sub clients have not been initialized."
        );
    }

    return {
        pubClient: redisPubClient,
        subClient: redisSubClient
    };
};

// ==========================================
// 4. CONNECT ALL REDIS CLIENTS
// ==========================================

export const connectRedis = async () => {
    const client = getRedisClient();

    try {
        // Connect main Redis client.

        if (client.status === "wait") {
            await client.connect();
        }

        const mainResponse = await client.ping();

        if (mainResponse !== "PONG") {
            throw new Error(
                "Main Redis health check failed."
            );
        }

        console.log("Redis main health check passed.");

        // Create dedicated Pub/Sub connections.

        redisPubClient = client.duplicate();
        redisSubClient = client.duplicate();

        redisPubClient.on("error", (error) => {
            console.error(
                "Redis publisher error:",
                error.message
            );
        });

        redisSubClient.on("error", (error) => {
            console.error(
                "Redis subscriber error:",
                error.message
            );
        });

        // Connect publisher and subscriber.

        await Promise.all([
            redisPubClient.connect(),
            redisSubClient.connect()
        ]);

        // Verify both connections.

        const [pubResponse, subResponse] =
            await Promise.all([
                redisPubClient.ping(),
                redisSubClient.ping()
            ]);

        if (
            pubResponse !== "PONG" ||
            subResponse !== "PONG"
        ) {
            throw new Error(
                "Redis Pub/Sub health check failed."
            );
        }

        console.log("Redis publisher initialized.");
        console.log("Redis subscriber initialized.");
        console.log("Redis Pub/Sub health checks passed.");

        return client;

    } catch (error) {
        console.error(
            "Redis startup failed:",
            error.message
        );

        await closeRedis();

        throw error;
    }
};

// ==========================================
// 5. CLOSE ALL REDIS CONNECTIONS
// ==========================================

export const closeRedis = async () => {
    const clients = [
        redisSubClient,
        redisPubClient,
        redisClient
    ];

    for (const client of clients) {
        if (!client) continue;

        try {
            if (client.status !== "end") {
                await client.quit();
            }
        } catch {
            client.disconnect();
        }
    }

    redisSubClient = null;
    redisPubClient = null;
    redisClient = null;

    console.log(
        "All SecureX Redis connections closed safely."
    );
};
