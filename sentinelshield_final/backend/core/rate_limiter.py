# ─────────────────────────────────────────────────────────────────
#  core/rate_limiter.py — Redis-Based Rate Limiting
#
#  WHAT IS RATE LIMITING?
#  Imagine someone knocking on your door 1000 times per minute.
#  Even if each knock is "polite", the sheer volume is an attack.
#  Rate limiting says: "After 100 knocks per minute, you're blocked."
#
#  REAL-WORLD ATTACKS RATE LIMITING PREVENTS:
#  • Brute-force login  — trying 10,000 passwords per minute
#  • DDoS              — flooding server with requests to crash it
#  • Credential stuffing — testing stolen username/password lists
#  • Web scraping abuse — hammering your API to steal all your data
#
#  HOW SLIDING WINDOW WORKS:
#  Fixed window:   "100 requests per minute, window resets at :00"
#                  Problem: 100 at :59 + 100 at :01 = 200 in 2 seconds!
#
#  Sliding window: "100 requests in any rolling 60-second window"
#                  Always fair — no boundary exploitation
#
#  WHY REDIS?
#  Redis is an in-memory database — extremely fast (microseconds).
#  We use it to count requests per IP in real-time.
#  Without Redis, we'd need to query SQLite for every request = slow.
# ─────────────────────────────────────────────────────────────────

import time
import sys
import os
from typing import Tuple, Optional
from dataclasses import dataclass

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from config import (
    REDIS_HOST, REDIS_PORT, REDIS_DB,
    RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SEC
)

# Try to import Redis — graceful fallback if not running
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


@dataclass
class RateLimitResult:
    """Result of a rate limit check."""
    is_limited:    bool    # True if this IP should be blocked
    request_count: int     # How many requests this IP made in window
    limit:         int     # What the limit is
    window_sec:    int     # Window size in seconds
    retry_after:   int     # Seconds until they can try again (0 if not limited)
    remaining:     int     # How many requests they have left


class RateLimiter:
    """
    Sliding window rate limiter using Redis.

    Each IP gets its own counter in Redis.
    We use Redis's atomic INCR command so concurrent requests
    are handled safely (no race conditions).

    FALLBACK: If Redis is not running, rate limiting is disabled
    and a warning is shown. The rest of SentinelShield still works.
    """

    def __init__(self):
        self.redis_client: Optional[object] = None
        self.available = False
        self._connect()

    def _connect(self):
        """Try to connect to Redis."""
        if not REDIS_AVAILABLE:
            print("⚠️  Redis package not installed. Rate limiting disabled.")
            return

        try:
            self.redis_client = redis.Redis(
                host         = REDIS_HOST,
                port         = REDIS_PORT,
                db           = REDIS_DB,
                decode_responses = True,
                socket_connect_timeout = 2,  # Don't wait more than 2 seconds
            )
            # Test the connection
            self.redis_client.ping()
            self.available = True
            print(f"✅ Redis connected at {REDIS_HOST}:{REDIS_PORT}")

        except Exception as e:
            print(f"⚠️  Redis not available ({e}). Rate limiting disabled.")
            print("   To enable: install Redis and run: redis-server")
            self.available = False

    def check(
        self,
        ip_address:  str,
        limit:       int = None,
        window_sec:  int = None,
        endpoint:    str = "global",
    ) -> RateLimitResult:
        """
        Check if an IP has exceeded the rate limit.

        Args:
            ip_address: The client's IP address
            limit:      Max requests allowed (default from config)
            window_sec: Time window in seconds (default from config)
            endpoint:   Which endpoint (allows different limits per route)

        Returns:
            RateLimitResult with is_limited=True if rate limit exceeded
        """
        limit      = limit      or RATE_LIMIT_REQUESTS
        window_sec = window_sec or RATE_LIMIT_WINDOW_SEC

        # If Redis is unavailable, always allow (graceful degradation)
        if not self.available or not self.redis_client:
            return RateLimitResult(
                is_limited=False, request_count=0, limit=limit,
                window_sec=window_sec, retry_after=0, remaining=limit
            )

        try:
            # Redis key format: "rate:global:192.168.1.1"
            key = f"rate:{endpoint}:{ip_address}"

            # Use Redis pipeline for atomic operations (faster + thread-safe)
            pipe = self.redis_client.pipeline()
            now  = int(time.time())

            # Sliding window using Redis sorted sets:
            # Each request is stored as: {timestamp: timestamp}
            # We remove old entries outside the window, then count remaining

            # Remove requests older than our window
            pipe.zremrangebyscore(key, 0, now - window_sec)
            # Add this request with current timestamp
            pipe.zadd(key, {str(now) + str(time.time_ns()): now})
            # Count requests in window
            pipe.zcard(key)
            # Set expiry so Redis auto-cleans old keys
            pipe.expire(key, window_sec * 2)

            _, _, request_count, _ = pipe.execute()

            is_limited = request_count > limit
            remaining  = max(0, limit - request_count)
            retry_after = window_sec if is_limited else 0

            return RateLimitResult(
                is_limited    = is_limited,
                request_count = request_count,
                limit         = limit,
                window_sec    = window_sec,
                retry_after   = retry_after,
                remaining     = remaining,
            )

        except Exception as e:
            print(f"⚠️  Rate limit check failed: {e}")
            # On error, allow the request (don't block legitimate users)
            return RateLimitResult(
                is_limited=False, request_count=0, limit=limit,
                window_sec=window_sec, retry_after=0, remaining=limit
            )

    def get_ip_stats(self, ip_address: str) -> dict:
        """Get rate limit stats for a specific IP — useful for dashboard."""
        if not self.available:
            return {"available": False}

        try:
            now    = int(time.time())
            key    = f"rate:global:{ip_address}"
            window = RATE_LIMIT_WINDOW_SEC

            # Remove old entries first
            self.redis_client.zremrangebyscore(key, 0, now - window)
            count = self.redis_client.zcard(key)

            return {
                "ip":            ip_address,
                "requests":      count,
                "limit":         RATE_LIMIT_REQUESTS,
                "window_sec":    window,
                "remaining":     max(0, RATE_LIMIT_REQUESTS - count),
                "is_limited":    count > RATE_LIMIT_REQUESTS,
            }
        except Exception:
            return {"available": False}

    def reset_ip(self, ip_address: str):
        """Reset rate limit counter for an IP (e.g., after unbanning)."""
        if self.available:
            try:
                self.redis_client.delete(f"rate:global:{ip_address}")
            except Exception:
                pass


# ── Singleton ─────────────────────────────────────────────────────
rate_limiter = RateLimiter()
