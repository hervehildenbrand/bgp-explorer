"""bgp-radar subprocess client for real-time BGP anomaly detection."""

import asyncio
import json
import os
import shutil
from datetime import timedelta
from typing import AsyncIterator, Optional

from bgp_explorer.cache.ttl_cache import TTLCache
from bgp_explorer.models.event import BGPEvent, EventType, Severity
from bgp_explorer.sources.base import DataSource


class BgpRadarError(Exception):
    """Exception raised for bgp-radar errors."""

    pass


class BgpRadarClient(DataSource):
    """Client for bgp-radar subprocess.

    Spawns bgp-radar as a subprocess, reads JSON events from stdout,
    and provides methods to query recent anomalies.

    The bgp-radar binary must be installed separately:
    `go install github.com/hervehildenbrand/bgp-radar/cmd/bgp-radar@latest`
    """

    def __init__(
        self,
        binary_path: Optional[str] = None,
        collectors: Optional[list[str]] = None,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        cache_ttl: timedelta = timedelta(minutes=5),
        max_recent_events: int = 1000,
    ):
        """Initialize the client.

        Args:
            binary_path: Path to bgp-radar binary. Falls back to BGP_RADAR_PATH
                         env var or PATH lookup.
            collectors: List of RIS collectors to monitor (default: ["rrc00"]).
            max_retries: Maximum retry attempts on failure.
            retry_delay: Delay between retries in seconds.
            cache_ttl: TTL for event cache.
            max_recent_events: Maximum number of recent events to keep.
        """
        self._binary_path = binary_path or os.environ.get("BGP_RADAR_PATH") or "bgp-radar"
        self._collectors = collectors or ["rrc00"]
        self._max_retries = max_retries
        self._retry_delay = retry_delay
        self._max_recent_events = max_recent_events

        self._process: Optional[asyncio.subprocess.Process] = None
        self._event_cache = TTLCache(default_ttl=cache_ttl)
        self._recent_events: list[BGPEvent] = []
        self._reader_task: Optional[asyncio.Task] = None
        self._running = False

    @property
    def is_running(self) -> bool:
        """Check if bgp-radar process is running."""
        return self._running and self._process is not None

    async def connect(self) -> None:
        """Start the bgp-radar subprocess."""
        await self.start()

    async def disconnect(self) -> None:
        """Stop the bgp-radar subprocess."""
        await self.stop()

    async def is_available(self) -> bool:
        """Check if bgp-radar binary is available.

        Returns:
            True if the binary exists and is executable.
        """
        # Check if it's an absolute path
        if os.path.isabs(self._binary_path):
            return os.path.isfile(self._binary_path) and os.access(
                self._binary_path, os.X_OK
            )

        # Check in PATH
        return shutil.which(self._binary_path) is not None

    async def start(self, collectors: Optional[list[str]] = None) -> None:
        """Start the bgp-radar subprocess.

        Args:
            collectors: Override collectors list for this session.

        Raises:
            BgpRadarError: If bgp-radar fails to start after retries.
        """
        if self._running:
            return

        if collectors:
            self._collectors = collectors

        retries = 0
        last_error = None

        while retries < self._max_retries:
            try:
                await self._start_process()
                self._running = True

                # Start background reader task
                self._reader_task = asyncio.create_task(self._read_events())
                return

            except Exception as e:
                last_error = e
                retries += 1
                if retries < self._max_retries:
                    await asyncio.sleep(self._retry_delay * retries)

        raise BgpRadarError(
            f"Failed to start bgp-radar after {self._max_retries} attempts: {last_error}"
        )

    async def _start_process(self) -> None:
        """Start the bgp-radar subprocess."""
        collectors_arg = ",".join(self._collectors)
        cmd = [self._binary_path, f"-collectors={collectors_arg}"]

        self._process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    async def stop(self) -> None:
        """Stop the bgp-radar subprocess gracefully."""
        self._running = False

        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
            self._reader_task = None

        if self._process:
            try:
                self._process.terminate()
                # Wait for graceful shutdown
                try:
                    await asyncio.wait_for(self._process.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    self._process.kill()
                    await self._process.wait()
            except ProcessLookupError:
                pass  # Process already terminated
            self._process = None

    async def _read_events(self) -> None:
        """Background task to read events from stdout."""
        if not self._process or not self._process.stdout:
            return

        try:
            async for line in self._process.stdout:
                if not self._running:
                    break

                line_str = line.decode("utf-8").strip()
                if not line_str:
                    continue

                event = self._parse_event(line_str)
                if event:
                    await self._add_event(event)

        except asyncio.CancelledError:
            pass
        except Exception:
            pass  # Log in production

    def _parse_event(self, json_line: str) -> Optional[BGPEvent]:
        """Parse a JSON line into a BGPEvent.

        Args:
            json_line: JSON string from bgp-radar stdout.

        Returns:
            BGPEvent if valid event, None otherwise.
        """
        try:
            data = json.loads(json_line)

            # Check if this is an event (has type field with known event type)
            event_type = data.get("type")
            if event_type not in ("hijack", "leak", "blackhole"):
                return None

            return BGPEvent.from_bgp_radar(data)

        except (json.JSONDecodeError, KeyError, ValueError):
            return None

    async def _add_event(self, event: BGPEvent) -> None:
        """Add an event to the cache and recent events list.

        Args:
            event: BGPEvent to add.
        """
        # Add to recent events list
        self._recent_events.append(event)

        # Trim if over limit
        if len(self._recent_events) > self._max_recent_events:
            self._recent_events = self._recent_events[-self._max_recent_events :]

        # Also cache with unique key
        cache_key = f"{event.type.value}:{event.affected_prefix}:{event.detected_at.isoformat()}"
        await self._event_cache.set(cache_key, event)

    async def get_recent_anomalies(
        self,
        event_type: Optional[EventType] = None,
        prefix: Optional[str] = None,
        asn: Optional[int] = None,
    ) -> list[BGPEvent]:
        """Get recent anomaly events with optional filtering.

        Args:
            event_type: Filter by event type (hijack, leak, blackhole).
            prefix: Filter by affected prefix.
            asn: Filter by affected ASN.

        Returns:
            List of matching BGPEvent objects.
        """
        events = self._recent_events.copy()

        if event_type:
            events = [e for e in events if e.type == event_type]

        if prefix:
            events = [e for e in events if e.affected_prefix == prefix]

        if asn:
            events = [e for e in events if e.affected_asn == asn]

        return events

    async def stream_anomalies(self) -> AsyncIterator[BGPEvent]:
        """Async iterator for streaming anomaly events.

        Yields:
            BGPEvent objects as they arrive.

        Note:
            The bgp-radar process must be started before calling this.
        """
        if not self._process or not self._process.stdout:
            raise BgpRadarError("bgp-radar process not running")

        async for line in self._process.stdout:
            if not self._running:
                break

            line_str = line.decode("utf-8").strip()
            if not line_str:
                continue

            event = self._parse_event(line_str)
            if event:
                await self._add_event(event)
                yield event
