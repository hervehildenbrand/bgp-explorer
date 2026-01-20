"""Tests for BGP Explorer Agent."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bgp_explorer.agent import BGPExplorerAgent
from bgp_explorer.config import Settings
from bgp_explorer.output import OutputFormatter


class TestAgentMonitorCommand:
    """Tests for /monitor command handling."""

    @pytest.fixture
    def settings(self):
        """Create test settings."""
        return Settings(
            anthropic_api_key="test-key",
        )

    @pytest.fixture
    def output(self):
        """Create mock output formatter."""
        mock = MagicMock(spec=OutputFormatter)
        mock.display_info = MagicMock()
        mock.display_error = MagicMock()
        return mock

    @pytest.fixture
    def mock_bgp_radar(self):
        """Create mock bgp-radar client."""
        mock = AsyncMock()
        mock.is_running = False
        mock._collectors = ["rrc00"]
        mock.is_available = AsyncMock(return_value=True)
        mock.start = AsyncMock()
        mock.stop = AsyncMock()
        mock.set_event_callback = MagicMock()
        return mock

    @pytest.mark.asyncio
    async def test_monitor_start_command(self, settings, output, mock_bgp_radar):
        """Test /monitor start command."""
        agent = BGPExplorerAgent(settings=settings, output=output)
        agent._bgp_radar = mock_bgp_radar
        agent._running = True

        result = await agent.handle_command("monitor start")

        assert result is True
        mock_bgp_radar.start.assert_called_once()
        output.display_info.assert_called()

    @pytest.mark.asyncio
    async def test_monitor_stop_command(self, settings, output, mock_bgp_radar):
        """Test /monitor stop command."""
        agent = BGPExplorerAgent(settings=settings, output=output)
        agent._bgp_radar = mock_bgp_radar
        mock_bgp_radar.is_running = True
        agent._running = True

        result = await agent.handle_command("monitor stop")

        assert result is True
        mock_bgp_radar.stop.assert_called_once()
        output.display_info.assert_called()

    @pytest.mark.asyncio
    async def test_monitor_status_command_running(self, settings, output, mock_bgp_radar):
        """Test /monitor status command when running."""
        agent = BGPExplorerAgent(settings=settings, output=output)
        agent._bgp_radar = mock_bgp_radar
        mock_bgp_radar.is_running = True
        agent._running = True

        result = await agent.handle_command("monitor status")

        assert result is True
        # Check that status message mentions running
        call_args = output.display_info.call_args_list
        assert any("running" in str(call).lower() for call in call_args)

    @pytest.mark.asyncio
    async def test_monitor_status_command_stopped(self, settings, output, mock_bgp_radar):
        """Test /monitor status command when stopped."""
        agent = BGPExplorerAgent(settings=settings, output=output)
        agent._bgp_radar = mock_bgp_radar
        mock_bgp_radar.is_running = False
        agent._running = True

        result = await agent.handle_command("monitor status")

        assert result is True
        # Check that status message mentions not running/stopped
        call_args = output.display_info.call_args_list
        assert any(
            "not running" in str(call).lower() or "stopped" in str(call).lower()
            for call in call_args
        )

    @pytest.mark.asyncio
    async def test_monitor_no_radar_available(self, settings, output):
        """Test /monitor command when bgp-radar not available."""
        agent = BGPExplorerAgent(settings=settings, output=output)
        agent._bgp_radar = None
        agent._running = True

        result = await agent.handle_command("monitor start")

        assert result is True
        output.display_error.assert_called()

    @pytest.mark.asyncio
    async def test_monitor_invalid_subcommand(self, settings, output, mock_bgp_radar):
        """Test /monitor with invalid subcommand."""
        agent = BGPExplorerAgent(settings=settings, output=output)
        agent._bgp_radar = mock_bgp_radar
        agent._running = True

        result = await agent.handle_command("monitor invalid")

        assert result is True
        # Should show usage info
        output.display_info.assert_called()


class TestAgentInitialization:
    """Tests for agent initialization."""

    @pytest.fixture
    def settings(self):
        """Create test settings."""
        return Settings(
            anthropic_api_key="test-key",
        )

    @pytest.fixture
    def output(self):
        """Create mock output formatter."""
        mock = MagicMock(spec=OutputFormatter)
        mock.display_info = MagicMock()
        return mock

    @pytest.mark.asyncio
    async def test_bgp_radar_not_auto_started(self, settings, output):
        """Test that bgp-radar is not auto-started during initialization."""
        with (
            patch("bgp_explorer.agent.BgpRadarClient") as MockBgpRadar,
            patch("bgp_explorer.agent.RipeStatClient") as MockRipeStat,
            patch("bgp_explorer.agent.GlobalpingClient") as MockGlobalping,
            patch("bgp_explorer.agent.PeeringDBClient") as MockPeeringDB,
            patch("bgp_explorer.agent.MonocleClient") as MockMonocle,
            patch("bgp_explorer.agent.ClaudeBackend") as MockClaude,
        ):
            # Setup mocks
            mock_bgp_radar = AsyncMock()
            mock_bgp_radar.is_available = AsyncMock(return_value=True)
            mock_bgp_radar.start = AsyncMock()
            mock_bgp_radar.set_event_callback = MagicMock()
            MockBgpRadar.return_value = mock_bgp_radar

            mock_ripe_stat = AsyncMock()
            MockRipeStat.return_value = mock_ripe_stat

            mock_globalping = AsyncMock()
            MockGlobalping.return_value = mock_globalping

            mock_peeringdb = AsyncMock()
            MockPeeringDB.return_value = mock_peeringdb

            mock_monocle = AsyncMock()
            mock_monocle.is_available = AsyncMock(return_value=True)
            MockMonocle.return_value = mock_monocle

            mock_claude = MagicMock()
            mock_claude.register_tool = MagicMock()
            MockClaude.return_value = mock_claude

            agent = BGPExplorerAgent(settings=settings, output=output)
            await agent.initialize()

            # Verify bgp-radar was NOT started
            mock_bgp_radar.start.assert_not_called()
            # But callback should be wired
            mock_bgp_radar.set_event_callback.assert_called_once()

    @pytest.mark.asyncio
    async def test_initialization_succeeds_without_bgp_radar(self, settings, output):
        """Test that initialization succeeds when bgp-radar is not available."""
        with (
            patch("bgp_explorer.agent.BgpRadarClient") as MockBgpRadar,
            patch("bgp_explorer.agent.RipeStatClient") as MockRipeStat,
            patch("bgp_explorer.agent.GlobalpingClient") as MockGlobalping,
            patch("bgp_explorer.agent.PeeringDBClient") as MockPeeringDB,
            patch("bgp_explorer.agent.MonocleClient") as MockMonocle,
            patch("bgp_explorer.agent.ClaudeBackend") as MockClaude,
        ):
            # Setup mocks - bgp-radar not available
            mock_bgp_radar = AsyncMock()
            mock_bgp_radar.is_available = AsyncMock(return_value=False)
            MockBgpRadar.return_value = mock_bgp_radar

            mock_ripe_stat = AsyncMock()
            MockRipeStat.return_value = mock_ripe_stat

            mock_globalping = AsyncMock()
            MockGlobalping.return_value = mock_globalping

            mock_peeringdb = AsyncMock()
            MockPeeringDB.return_value = mock_peeringdb

            mock_monocle = AsyncMock()
            mock_monocle.is_available = AsyncMock(return_value=True)
            MockMonocle.return_value = mock_monocle

            mock_claude = MagicMock()
            mock_claude.register_tool = MagicMock()
            MockClaude.return_value = mock_claude

            agent = BGPExplorerAgent(settings=settings, output=output)

            # Should succeed even without bgp-radar
            await agent.initialize()

            # Verify bgp-radar is None
            assert agent._bgp_radar is None

            # Verify warning was displayed
            call_args = [str(call) for call in output.display_info.call_args_list]
            assert any("bgp-radar not found" in arg for arg in call_args)

    @pytest.mark.asyncio
    async def test_initialization_fails_when_monocle_not_available(self, settings, output):
        """Test that initialization fails when monocle is not available."""
        with (
            patch("bgp_explorer.agent.BgpRadarClient") as MockBgpRadar,
            patch("bgp_explorer.agent.RipeStatClient") as MockRipeStat,
            patch("bgp_explorer.agent.GlobalpingClient") as MockGlobalping,
            patch("bgp_explorer.agent.PeeringDBClient") as MockPeeringDB,
            patch("bgp_explorer.agent.MonocleClient") as MockMonocle,
        ):
            # Setup mocks - bgp-radar available, monocle not available
            mock_bgp_radar = AsyncMock()
            mock_bgp_radar.is_available = AsyncMock(return_value=True)
            mock_bgp_radar.set_event_callback = MagicMock()
            MockBgpRadar.return_value = mock_bgp_radar

            mock_ripe_stat = AsyncMock()
            MockRipeStat.return_value = mock_ripe_stat

            mock_globalping = AsyncMock()
            MockGlobalping.return_value = mock_globalping

            mock_peeringdb = AsyncMock()
            MockPeeringDB.return_value = mock_peeringdb

            mock_monocle = AsyncMock()
            mock_monocle.is_available = AsyncMock(return_value=False)
            MockMonocle.return_value = mock_monocle

            agent = BGPExplorerAgent(settings=settings, output=output)

            # Should raise RuntimeError when monocle is not available
            with pytest.raises(RuntimeError, match="monocle"):
                await agent.initialize()
