"""Tests for TTL cache implementation."""

import asyncio
from datetime import timedelta

import pytest

from bgp_explorer.cache.ttl_cache import TTLCache


class TestTTLCache:
    """Tests for TTLCache."""

    @pytest.mark.asyncio
    async def test_set_and_get(self):
        """Test basic set and get operations."""
        cache = TTLCache(default_ttl=timedelta(minutes=5))
        await cache.set("key1", "value1")
        result = await cache.get("key1")
        assert result == "value1"

    @pytest.mark.asyncio
    async def test_get_nonexistent_key(self):
        """Test getting a key that doesn't exist."""
        cache = TTLCache()
        result = await cache.get("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_with_default(self):
        """Test getting with a default value."""
        cache = TTLCache()
        result = await cache.get("nonexistent", default="default_value")
        assert result == "default_value"

    @pytest.mark.asyncio
    async def test_delete(self):
        """Test deleting a key."""
        cache = TTLCache()
        await cache.set("key1", "value1")
        await cache.delete("key1")
        result = await cache.get("key1")
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent(self):
        """Test deleting a key that doesn't exist (should not raise)."""
        cache = TTLCache()
        await cache.delete("nonexistent")  # Should not raise

    @pytest.mark.asyncio
    async def test_ttl_expiration(self):
        """Test that entries expire after TTL."""
        cache = TTLCache(default_ttl=timedelta(milliseconds=50))
        await cache.set("key1", "value1")

        # Value should exist immediately
        assert await cache.get("key1") == "value1"

        # Wait for expiration
        await asyncio.sleep(0.1)

        # Value should be expired
        assert await cache.get("key1") is None

    @pytest.mark.asyncio
    async def test_custom_ttl_per_key(self):
        """Test setting custom TTL for specific keys."""
        cache = TTLCache(default_ttl=timedelta(minutes=5))
        await cache.set("short", "value", ttl=timedelta(milliseconds=50))
        await cache.set("long", "value", ttl=timedelta(minutes=5))

        await asyncio.sleep(0.1)

        # Short TTL should be expired
        assert await cache.get("short") is None
        # Long TTL should still exist
        assert await cache.get("long") == "value"

    @pytest.mark.asyncio
    async def test_cleanup(self):
        """Test cleanup of expired entries."""
        cache = TTLCache(default_ttl=timedelta(milliseconds=50))
        await cache.set("key1", "value1")
        await cache.set("key2", "value2")

        await asyncio.sleep(0.1)

        # Add a non-expired entry
        await cache.set("key3", "value3", ttl=timedelta(minutes=5))

        # Run cleanup
        removed = await cache.cleanup()
        assert removed == 2  # key1 and key2 should be removed

        # key3 should still exist
        assert await cache.get("key3") == "value3"

    @pytest.mark.asyncio
    async def test_clear(self):
        """Test clearing all entries."""
        cache = TTLCache()
        await cache.set("key1", "value1")
        await cache.set("key2", "value2")

        await cache.clear()

        assert await cache.get("key1") is None
        assert await cache.get("key2") is None

    @pytest.mark.asyncio
    async def test_contains(self):
        """Test checking if key exists."""
        cache = TTLCache()
        await cache.set("key1", "value1")

        assert await cache.contains("key1") is True
        assert await cache.contains("nonexistent") is False

    @pytest.mark.asyncio
    async def test_contains_expired(self):
        """Test that contains returns False for expired keys."""
        cache = TTLCache(default_ttl=timedelta(milliseconds=50))
        await cache.set("key1", "value1")

        await asyncio.sleep(0.1)

        assert await cache.contains("key1") is False

    @pytest.mark.asyncio
    async def test_size(self):
        """Test getting cache size."""
        cache = TTLCache()
        assert await cache.size() == 0

        await cache.set("key1", "value1")
        await cache.set("key2", "value2")
        assert await cache.size() == 2

    @pytest.mark.asyncio
    async def test_concurrent_access(self):
        """Test concurrent access to the cache."""
        cache = TTLCache()

        async def writer(key: str, value: str):
            await cache.set(key, value)

        async def reader(key: str):
            return await cache.get(key)

        # Write concurrently
        await asyncio.gather(*[writer(f"key{i}", f"value{i}") for i in range(100)])

        # Read concurrently
        results = await asyncio.gather(*[reader(f"key{i}") for i in range(100)])

        for i, result in enumerate(results):
            assert result == f"value{i}"

    @pytest.mark.asyncio
    async def test_overwrite_existing_key(self):
        """Test overwriting an existing key."""
        cache = TTLCache()
        await cache.set("key1", "value1")
        await cache.set("key1", "value2")

        result = await cache.get("key1")
        assert result == "value2"

    @pytest.mark.asyncio
    async def test_complex_values(self):
        """Test storing complex values."""
        cache = TTLCache()
        complex_value = {
            "list": [1, 2, 3],
            "nested": {"key": "value"},
            "tuple": (1, 2, 3),
        }
        await cache.set("complex", complex_value)

        result = await cache.get("complex")
        assert result == complex_value

    @pytest.mark.asyncio
    async def test_default_ttl(self):
        """Test that default TTL is 5 minutes."""
        cache = TTLCache()
        assert cache.default_ttl == timedelta(minutes=5)
