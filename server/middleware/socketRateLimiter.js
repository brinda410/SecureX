import { getRedisClient } from "../config/redis.js";

// Atomic Redis rate limiter using Lua.
const RATE_LIMIT_SCRIPT = `
    local current = redis.call("INCR", KEYS[1])

    if current == 1 then
        redis.call("PEXPIRE", KEYS[1], ARGV[1])
    end

    local ttl = redis.call("PTTL", KEYS[1])

    return { current, ttl }
`;

export const checkSocketRateLimit = async ({
    userId,
    eventName,
    limit,
    windowMs
}) => {
    if (!userId || !eventName || !limit || !windowMs) {
        throw new Error("Invalid Socket.IO rate-limit configuration.");
    }

    const redis = getRedisClient();

    const key = [
        "securex",
        "socket",
        "ratelimit",
        String(userId),
        String(eventName)
    ].join(":");

    const result = await redis.eval(
        RATE_LIMIT_SCRIPT,
        1,
        key,
        windowMs
    );

    const currentCount = Number(result[0]);
    const ttl = Number(result[1]);

    return {
        allowed: currentCount <= limit,
        limit,
        remaining: Math.max(0, limit - currentCount),
        retryAfterMs: Math.max(0, ttl)
    };
};
