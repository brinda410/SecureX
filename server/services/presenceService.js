import { getRedisClient } from "../config/redis.js";

const PRESENCE_TTL = 60 * 1000;

const ADD_PRESENCE_SCRIPT = `
    redis.call(
        "ZREMRANGEBYSCORE",
        KEYS[1],
        "-inf",
        ARGV[1]
    )

    redis.call(
        "ZADD",
        KEYS[1],
        ARGV[2],
        ARGV[3]
    )

    redis.call(
        "PEXPIRE",
        KEYS[1],
        ARGV[4]
    )

    return redis.call("ZCARD", KEYS[1])
`;

const REMOVE_PRESENCE_SCRIPT = `
    redis.call(
        "ZREM",
        KEYS[1],
        ARGV[1]
    )

    redis.call(
        "ZREMRANGEBYSCORE",
        KEYS[1],
        "-inf",
        ARGV[2]
    )

    local count = redis.call("ZCARD", KEYS[1])

    if count == 0 then
        redis.call("DEL", KEYS[1])
    end

    return count
`;

function getPresenceKey(userId) {
    return `securex:presence:${userId}`;
}

// Add or refresh a user's socket presence.

export async function addSocketPresence(userId, socketId) {
    const redis = getRedisClient();

    const now = Date.now();
    const expiresAt = now + PRESENCE_TTL;

    const count = await redis.eval(
        ADD_PRESENCE_SCRIPT,
        1,
        getPresenceKey(userId),
        now,
        expiresAt,
        socketId,
        PRESENCE_TTL
    );

    return Number(count);
}

// Remove a disconnected socket.

export async function removeSocketPresence(userId, socketId) {
    const redis = getRedisClient();

    const count = await redis.eval(
        REMOVE_PRESENCE_SCRIPT,
        1,
        getPresenceKey(userId),
        socketId,
        Date.now()
    );

    return Number(count);
}

// Check whether a user has an active connection.

export async function isUserOnline(userId) {
    const redis = getRedisClient();

    const key = getPresenceKey(userId);
    const now = Date.now();

    await redis.zremrangebyscore(
        key,
        "-inf",
        now
    );

    const count = await redis.zcard(key);

    return count > 0;
}
