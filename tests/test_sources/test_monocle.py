"""Tests for Monocle CLI client."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bgp_explorer.sources.monocle import MonocleClient


class TestMonocleClient:
    """Tests for MonocleClient."""

    @pytest.fixture
    def client(self):
        """Create a MonocleClient instance."""
        return MonocleClient(binary_path="/usr/local/bin/monocle")

    @pytest.mark.asyncio
    async def test_connect_is_noop(self, client):
        """Test that connect is a no-op."""
        await client.connect()  # Should not raise

    @pytest.mark.asyncio
    async def test_disconnect_is_noop(self, client):
        """Test that disconnect is a no-op."""
        await client.disconnect()  # Should not raise

    @pytest.mark.asyncio
    async def test_is_available_binary_not_found(self):
        """Test is_available returns False when binary not found."""
        client = MonocleClient(binary_path="/nonexistent/path/monocle")
        available = await client.is_available()
        assert available is False

    @pytest.mark.asyncio
    async def test_is_available_no_path(self):
        """Test is_available returns False when no binary path."""
        client = MonocleClient(binary_path=None)
        # Mock shutil.which to return None
        with patch("shutil.which", return_value=None):
            client._binary_path = None
            available = await client.is_available()
            assert available is False

    @pytest.mark.asyncio
    async def test_binary_path_from_env(self):
        """Test binary path can be set from environment."""
        with patch.dict("os.environ", {"MONOCLE_PATH": "/custom/path/monocle"}):
            client = MonocleClient()
            assert client._binary_path == "/custom/path/monocle"

    @pytest.mark.asyncio
    async def test_get_as_relationships_success(self, client):
        """Test getting AS relationships successfully."""
        mock_output = {
            "max_peers_count": 1762,
            "results": [
                {
                    "asn1": 47957,
                    "asn2": 45666,
                    "asn2_name": "Worldline Services",
                    "connected": "47.7%",
                    "peer": "17.6%",
                    "as1_upstream": "30.1%",
                    "as2_upstream": "0.0%",
                },
                {
                    "asn1": 47957,
                    "asn2": 8677,
                    "asn2_name": "Worldline SA",
                    "connected": "41.8%",
                    "peer": "23.6%",
                    "as1_upstream": "18.2%",
                    "as2_upstream": "0.0%",
                },
            ],
        }

        async def mock_run(*args, **kwargs):
            mock_process = MagicMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(
                return_value=(json.dumps(mock_output).encode(), b"")
            )
            return mock_process

        with patch("asyncio.create_subprocess_exec", mock_run):
            relationships = await client.get_as_relationships(47957)

        assert len(relationships) == 2
        assert relationships[0].asn1 == 47957
        assert relationships[0].asn2 == 45666
        assert relationships[0].connected_pct == 47.7

    @pytest.mark.asyncio
    async def test_get_as_relationships_with_visibility_filter(self, client):
        """Test filtering relationships by minimum visibility."""
        mock_output = {
            "max_peers_count": 1762,
            "results": [
                {
                    "asn1": 47957,
                    "asn2": 45666,
                    "connected": "47.7%",
                    "peer": "17.6%",
                    "as1_upstream": "30.1%",
                    "as2_upstream": "0.0%",
                },
                {
                    "asn1": 47957,
                    "asn2": 99999,
                    "connected": "5.0%",
                    "peer": "2.0%",
                    "as1_upstream": "3.0%",
                    "as2_upstream": "0.0%",
                },
            ],
        }

        async def mock_run(*args, **kwargs):
            mock_process = MagicMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(
                return_value=(json.dumps(mock_output).encode(), b"")
            )
            return mock_process

        with patch("asyncio.create_subprocess_exec", mock_run):
            relationships = await client.get_as_relationships(47957, min_visibility=10.0)

        # Only the first relationship should pass the filter
        assert len(relationships) == 1
        assert relationships[0].asn2 == 45666

    @pytest.mark.asyncio
    async def test_get_as_peers(self, client):
        """Test getting peer relationships only."""
        mock_output = {
            "max_peers_count": 1762,
            "results": [
                {
                    "asn1": 47957,
                    "asn2": 8677,
                    "connected": "41.8%",
                    "peer": "23.6%",  # High peer % = peer relationship
                    "as1_upstream": "18.2%",
                    "as2_upstream": "0.0%",
                },
                {
                    "asn1": 47957,
                    "asn2": 3356,
                    "connected": "12.3%",
                    "peer": "0.0%",
                    "as1_upstream": "0.0%",
                    "as2_upstream": "12.3%",  # as2 is upstream
                },
            ],
        }

        async def mock_run(*args, **kwargs):
            mock_process = MagicMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(
                return_value=(json.dumps(mock_output).encode(), b"")
            )
            return mock_process

        with patch("asyncio.create_subprocess_exec", mock_run):
            peers = await client.get_as_peers(47957)

        # Only the peer relationship should be returned
        assert len(peers) == 1
        assert peers[0].asn2 == 8677
        assert peers[0].relationship_type == "peer"

    @pytest.mark.asyncio
    async def test_get_as_upstreams(self, client):
        """Test getting upstream relationships only."""
        mock_output = {
            "max_peers_count": 1762,
            "results": [
                {
                    "asn1": 47957,
                    "asn2": 3356,
                    "asn2_name": "Level3",
                    "connected": "12.3%",
                    "peer": "0.0%",
                    "as1_upstream": "0.0%",
                    "as2_upstream": "12.3%",  # as2 is upstream
                },
                {
                    "asn1": 47957,
                    "asn2": 8677,
                    "connected": "41.8%",
                    "peer": "23.6%",  # peer relationship
                    "as1_upstream": "18.2%",
                    "as2_upstream": "0.0%",
                },
            ],
        }

        async def mock_run(*args, **kwargs):
            mock_process = MagicMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(
                return_value=(json.dumps(mock_output).encode(), b"")
            )
            return mock_process

        with patch("asyncio.create_subprocess_exec", mock_run):
            upstreams = await client.get_as_upstreams(47957)

        # Only the upstream relationship should be returned
        assert len(upstreams) == 1
        assert upstreams[0].asn2 == 3356
        assert upstreams[0].relationship_type == "upstream"

    @pytest.mark.asyncio
    async def test_get_as_downstreams(self, client):
        """Test getting downstream relationships only."""
        mock_output = {
            "max_peers_count": 1762,
            "results": [
                {
                    "asn1": 47957,
                    "asn2": 45666,
                    "connected": "47.7%",
                    "peer": "17.6%",  # Not high enough for peer
                    "as1_upstream": "30.1%",  # as1 is upstream, so asn2 is downstream
                    "as2_upstream": "0.0%",
                },
                {
                    "asn1": 47957,
                    "asn2": 3356,
                    "connected": "12.3%",
                    "peer": "0.0%",
                    "as1_upstream": "0.0%",
                    "as2_upstream": "12.3%",  # upstream
                },
            ],
        }

        async def mock_run(*args, **kwargs):
            mock_process = MagicMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(
                return_value=(json.dumps(mock_output).encode(), b"")
            )
            return mock_process

        with patch("asyncio.create_subprocess_exec", mock_run):
            downstreams = await client.get_as_downstreams(47957)

        # Only the downstream relationship should be returned
        assert len(downstreams) == 1
        assert downstreams[0].asn2 == 45666
        assert downstreams[0].relationship_type == "downstream"

    @pytest.mark.asyncio
    async def test_check_relationship_found(self, client):
        """Test checking relationship between two ASes when found."""
        mock_output = {
            "max_peers_count": 1762,
            "results": [
                {
                    "asn1": 47957,
                    "asn2": 3356,
                    "asn2_name": "Level3",
                    "connected": "12.3%",
                    "peer": "0.0%",
                    "as1_upstream": "0.0%",
                    "as2_upstream": "12.3%",
                },
            ],
        }

        async def mock_run(*args, **kwargs):
            mock_process = MagicMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(
                return_value=(json.dumps(mock_output).encode(), b"")
            )
            return mock_process

        with patch("asyncio.create_subprocess_exec", mock_run):
            rel = await client.check_relationship(47957, 3356)

        assert rel is not None
        assert rel.asn1 == 47957
        assert rel.asn2 == 3356
        assert rel.relationship_type == "upstream"

    @pytest.mark.asyncio
    async def test_check_relationship_not_found(self, client):
        """Test checking relationship when none exists."""
        mock_output = {
            "max_peers_count": 1762,
            "results": [],
        }

        async def mock_run(*args, **kwargs):
            mock_process = MagicMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(
                return_value=(json.dumps(mock_output).encode(), b"")
            )
            return mock_process

        with patch("asyncio.create_subprocess_exec", mock_run):
            rel = await client.check_relationship(47957, 99999)

        assert rel is None

    @pytest.mark.asyncio
    async def test_get_connectivity(self, client):
        """Test getting connectivity summary."""
        mock_output = {
            "queries": [
                {
                    "query": "47957",
                    "query_type": "asn",
                    "connectivity": {
                        "summary": {
                            "asn": 47957,
                            "upstreams": {
                                "count": 7,
                                "percent": 0.39,
                                "top": [
                                    {
                                        "asn": 4826,
                                        "name": "VOCUS-BACKBONE-AS",
                                        "peers_count": 378,
                                        "peers_percent": 21.45,
                                    },
                                    {
                                        "asn": 3356,
                                        "name": "LEVEL3",
                                        "peers_count": 217,
                                        "peers_percent": 12.32,
                                    },
                                ],
                            },
                            "peers": {
                                "count": 1774,
                                "percent": 99.11,
                                "top": [
                                    {
                                        "asn": 45666,
                                        "name": "Worldline Services",
                                        "peers_count": 841,
                                        "peers_percent": 47.73,
                                    },
                                ],
                            },
                            "downstreams": {
                                "count": 9,
                                "percent": 0.50,
                                "top": [],
                            },
                        },
                    },
                },
            ],
        }

        async def mock_run(*args, **kwargs):
            mock_process = MagicMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(
                return_value=(json.dumps(mock_output).encode(), b"")
            )
            return mock_process

        with patch("asyncio.create_subprocess_exec", mock_run):
            connectivity = await client.get_connectivity(47957)

        assert connectivity.asn == 47957
        assert connectivity.total_neighbors == 7 + 1774 + 9
        assert len(connectivity.upstreams) == 2
        assert len(connectivity.peers) == 1
        assert len(connectivity.downstreams) == 0
        assert connectivity.upstreams[0].asn == 4826

    @pytest.mark.asyncio
    async def test_run_command_binary_not_found(self):
        """Test _run_command raises when binary not found."""
        client = MonocleClient(binary_path=None)
        with patch("shutil.which", return_value=None):
            client._binary_path = None
            with pytest.raises(RuntimeError, match="Monocle binary not found"):
                await client._run_command(["as2rel", "47957"])

    @pytest.mark.asyncio
    async def test_run_command_timeout(self, client):
        """Test _run_command raises on timeout."""

        async def mock_run(*args, **kwargs):
            mock_process = MagicMock()

            async def slow_communicate():
                await asyncio.sleep(10)  # Simulate slow command
                return (b"", b"")

            mock_process.communicate = slow_communicate
            mock_process.kill = MagicMock()
            return mock_process

        client._timeout = 0.1  # Very short timeout

        with patch("asyncio.create_subprocess_exec", mock_run):
            with pytest.raises(TimeoutError):
                await client._run_command(["as2rel", "47957"])

    @pytest.mark.asyncio
    async def test_run_command_non_zero_exit(self, client):
        """Test _run_command raises on non-zero exit code."""

        async def mock_run(*args, **kwargs):
            mock_process = MagicMock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(return_value=(b"", b"Command failed"))
            return mock_process

        with patch("asyncio.create_subprocess_exec", mock_run):
            with pytest.raises(RuntimeError, match="Monocle command failed"):
                await client._run_command(["as2rel", "invalid"])

    @pytest.mark.asyncio
    async def test_run_command_invalid_json(self, client):
        """Test _run_command raises on invalid JSON output."""

        async def mock_run(*args, **kwargs):
            mock_process = MagicMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"not valid json", b""))
            return mock_process

        with patch("asyncio.create_subprocess_exec", mock_run):
            with pytest.raises(RuntimeError, match="Failed to parse Monocle JSON"):
                await client._run_command(["as2rel", "47957"])

    @pytest.mark.asyncio
    async def test_use_cache_flag(self):
        """Test that use_cache=True adds --no-refresh flag."""
        client = MonocleClient(binary_path="/usr/local/bin/monocle", use_cache=True)
        mock_output = {"results": []}

        captured_args = []

        async def mock_run(*args, **kwargs):
            captured_args.extend(args)
            mock_process = MagicMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(
                return_value=(json.dumps(mock_output).encode(), b"")
            )
            return mock_process

        with patch("asyncio.create_subprocess_exec", mock_run):
            await client._run_command(["as2rel", "47957"])

        assert "--no-refresh" in captured_args

    @pytest.mark.asyncio
    async def test_no_cache_flag(self):
        """Test that use_cache=False omits --no-refresh flag."""
        client = MonocleClient(binary_path="/usr/local/bin/monocle", use_cache=False)
        mock_output = {"results": []}

        captured_args = []

        async def mock_run(*args, **kwargs):
            captured_args.extend(args)
            mock_process = MagicMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(
                return_value=(json.dumps(mock_output).encode(), b"")
            )
            return mock_process

        with patch("asyncio.create_subprocess_exec", mock_run):
            await client._run_command(["as2rel", "47957"])

        assert "--no-refresh" not in captured_args

    @pytest.mark.asyncio
    async def test_run_command_bare_array_response(self, client):
        """Test that _run_command normalizes bare JSON array to dict with results key."""
        # Monocle returns bare [] when no results found (e.g., as2rel with two ASNs)
        bare_array = [
            {
                "asn1": 13335,
                "asn2": 15169,
                "connected": "50.0%",
                "peer": "50.0%",
                "as1_upstream": "0.0%",
                "as2_upstream": "0.0%",
            }
        ]

        async def mock_run(*args, **kwargs):
            mock_process = MagicMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(
                return_value=(json.dumps(bare_array).encode(), b"")
            )
            return mock_process

        with patch("asyncio.create_subprocess_exec", mock_run):
            result = await client._run_command(["as2rel", "13335", "15169"])

        # Should be wrapped in {"results": [...]}
        assert isinstance(result, dict)
        assert "results" in result
        assert len(result["results"]) == 1

    @pytest.mark.asyncio
    async def test_run_command_bare_empty_array_response(self, client):
        """Test that _run_command normalizes bare empty JSON array to dict."""
        async def mock_run(*args, **kwargs):
            mock_process = MagicMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(
                return_value=(json.dumps([]).encode(), b"")
            )
            return mock_process

        with patch("asyncio.create_subprocess_exec", mock_run):
            result = await client._run_command(["as2rel", "13335", "15169"])

        assert isinstance(result, dict)
        assert "results" in result
        assert len(result["results"]) == 0

    @pytest.mark.asyncio
    async def test_check_relationship_bare_empty_array(self, client):
        """Test check_relationship handles monocle returning bare empty array."""
        async def mock_run(*args, **kwargs):
            mock_process = MagicMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(
                return_value=(json.dumps([]).encode(), b"")
            )
            return mock_process

        with patch("asyncio.create_subprocess_exec", mock_run):
            rel = await client.check_relationship(13335, 15169)

        assert rel is None

    @pytest.mark.asyncio
    async def test_get_connectivity_no_queries(self, client):
        """Test get_connectivity raises when no queries returned."""
        mock_output = {"queries": []}

        async def mock_run(*args, **kwargs):
            mock_process = MagicMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(
                return_value=(json.dumps(mock_output).encode(), b"")
            )
            return mock_process

        with patch("asyncio.create_subprocess_exec", mock_run):
            with pytest.raises(RuntimeError, match="No data returned"):
                await client.get_connectivity(99999)

    @pytest.mark.asyncio
    async def test_get_connectivity_no_summary(self, client):
        """Test get_connectivity raises when no summary in response."""
        mock_output = {
            "queries": [
                {
                    "query": "99999",
                    "connectivity": {},
                },
            ],
        }

        async def mock_run(*args, **kwargs):
            mock_process = MagicMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(
                return_value=(json.dumps(mock_output).encode(), b"")
            )
            return mock_process

        with patch("asyncio.create_subprocess_exec", mock_run):
            with pytest.raises(RuntimeError, match="No connectivity data"):
                await client.get_connectivity(99999)
