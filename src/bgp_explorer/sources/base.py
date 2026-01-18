"""Abstract base class for data source clients."""

from abc import ABC, abstractmethod
from typing import Any


class DataSource(ABC):
    """Abstract base class for BGP data source clients.

    All data source implementations should inherit from this class
    and implement the required methods.
    """

    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to the data source."""
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection to the data source."""
        pass

    @abstractmethod
    async def is_available(self) -> bool:
        """Check if the data source is available.

        Returns:
            True if the data source is reachable and operational.
        """
        pass

    async def __aenter__(self) -> "DataSource":
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.disconnect()
