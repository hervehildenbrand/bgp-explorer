"""Async-safe TTL cache implementation."""

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any


@dataclass
class CacheEntry:
    """A single cache entry with expiration time."""

    value: Any
    expires_at: datetime


class TTLCache:
    """Async-safe in-memory cache with TTL (time-to-live) support.

    Thread-safe for concurrent access using asyncio locks.
    Default TTL is 5 minutes.

    Example:
        cache = TTLCache(default_ttl=timedelta(minutes=5))
        await cache.set("key", "value")
        result = await cache.get("key")
    """

    def __init__(self, default_ttl: timedelta = timedelta(minutes=5)):
        """Initialize the cache.

        Args:
            default_ttl: Default time-to-live for cache entries.
        """
        self._cache: dict[str, CacheEntry] = {}
        self._lock = asyncio.Lock()
        self.default_ttl = default_ttl

    async def get(self, key: str, default: Any = None) -> Any:
        """Get a value from the cache.

        Args:
            key: The cache key.
            default: Value to return if key doesn't exist or is expired.

        Returns:
            The cached value or the default.
        """
        async with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return default

            # Check if expired
            if datetime.now(UTC) > entry.expires_at:
                del self._cache[key]
                return default

            return entry.value

    async def set(
        self, key: str, value: Any, ttl: timedelta | None = None
    ) -> None:
        """Set a value in the cache.

        Args:
            key: The cache key.
            value: The value to cache.
            ttl: Custom TTL for this entry. Uses default_ttl if not provided.
        """
        if ttl is None:
            ttl = self.default_ttl

        expires_at = datetime.now(UTC) + ttl

        async with self._lock:
            self._cache[key] = CacheEntry(value=value, expires_at=expires_at)

    async def delete(self, key: str) -> None:
        """Delete a key from the cache.

        Args:
            key: The cache key to delete.
        """
        async with self._lock:
            self._cache.pop(key, None)

    async def contains(self, key: str) -> bool:
        """Check if a key exists and is not expired.

        Args:
            key: The cache key.

        Returns:
            True if the key exists and is not expired.
        """
        async with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return False

            if datetime.now(UTC) > entry.expires_at:
                del self._cache[key]
                return False

            return True

    async def cleanup(self) -> int:
        """Remove all expired entries from the cache.

        Returns:
            Number of entries removed.
        """
        async with self._lock:
            now = datetime.now(UTC)
            expired_keys = [
                key
                for key, entry in self._cache.items()
                if now > entry.expires_at
            ]

            for key in expired_keys:
                del self._cache[key]

            return len(expired_keys)

    async def clear(self) -> None:
        """Remove all entries from the cache."""
        async with self._lock:
            self._cache.clear()

    async def size(self) -> int:
        """Get the number of entries in the cache (including expired).

        Returns:
            Number of cache entries.
        """
        async with self._lock:
            return len(self._cache)
