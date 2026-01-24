"""Tests for dynamic prompt builder."""

from bgp_explorer.ai.prompt_builder import (
    BGP_RADAR_SECTION,
    BGP_RADAR_UNAVAILABLE,
    CORE_PROMPT,
    GLOBALPING_SECTION,
    GLOBALPING_UNAVAILABLE,
    MONOCLE_SECTION,
    MONOCLE_UNAVAILABLE,
    PEERINGDB_SECTION,
    PEERINGDB_UNAVAILABLE,
    AvailableTools,
    PromptBuilder,
)


class TestAvailableTools:
    """Tests for AvailableTools dataclass."""

    def test_default_all_unavailable(self):
        """Test that all tools default to unavailable."""
        available = AvailableTools()
        assert available.bgp_radar is False
        assert available.globalping is False
        assert available.peeringdb is False
        assert available.monocle is False

    def test_set_individual_tools(self):
        """Test setting individual tool availability."""
        available = AvailableTools(monocle=True, peeringdb=True)
        assert available.monocle is True
        assert available.peeringdb is True
        assert available.bgp_radar is False
        assert available.globalping is False

    def test_all_tools_available(self):
        """Test all tools available configuration."""
        available = AvailableTools(
            bgp_radar=True,
            globalping=True,
            peeringdb=True,
            monocle=True,
        )
        assert available.bgp_radar is True
        assert available.globalping is True
        assert available.peeringdb is True
        assert available.monocle is True


class TestPromptBuilder:
    """Tests for PromptBuilder class."""

    def test_core_prompt_always_included(self):
        """Test that core prompt is always present regardless of tool availability."""
        builder = PromptBuilder()

        # Test with no tools
        prompt_none = builder.build(AvailableTools())
        assert CORE_PROMPT in prompt_none

        # Test with all tools
        prompt_all = builder.build(
            AvailableTools(bgp_radar=True, globalping=True, peeringdb=True, monocle=True)
        )
        assert CORE_PROMPT in prompt_all

    def test_monocle_section_when_available(self):
        """Test monocle section included when available."""
        builder = PromptBuilder()
        prompt = builder.build(AvailableTools(monocle=True))

        assert MONOCLE_SECTION in prompt
        assert MONOCLE_UNAVAILABLE not in prompt

    def test_monocle_unavailable_message_when_not_available(self):
        """Test monocle unavailable message when not available."""
        builder = PromptBuilder()
        prompt = builder.build(AvailableTools(monocle=False))

        assert MONOCLE_UNAVAILABLE in prompt
        assert MONOCLE_SECTION not in prompt

    def test_bgp_radar_section_when_available(self):
        """Test bgp-radar section included when available."""
        builder = PromptBuilder()
        prompt = builder.build(AvailableTools(bgp_radar=True))

        assert BGP_RADAR_SECTION in prompt
        assert BGP_RADAR_UNAVAILABLE not in prompt

    def test_bgp_radar_unavailable_message_when_not_available(self):
        """Test bgp-radar unavailable message when not available."""
        builder = PromptBuilder()
        prompt = builder.build(AvailableTools(bgp_radar=False))

        assert BGP_RADAR_UNAVAILABLE in prompt
        assert BGP_RADAR_SECTION not in prompt

    def test_globalping_section_when_available(self):
        """Test globalping section included when available."""
        builder = PromptBuilder()
        prompt = builder.build(AvailableTools(globalping=True))

        assert GLOBALPING_SECTION in prompt
        assert GLOBALPING_UNAVAILABLE not in prompt

    def test_globalping_unavailable_message_when_not_available(self):
        """Test globalping unavailable message when not available."""
        builder = PromptBuilder()
        prompt = builder.build(AvailableTools(globalping=False))

        assert GLOBALPING_UNAVAILABLE in prompt
        assert GLOBALPING_SECTION not in prompt

    def test_peeringdb_section_when_available(self):
        """Test peeringdb section included when available."""
        builder = PromptBuilder()
        prompt = builder.build(AvailableTools(peeringdb=True))

        assert PEERINGDB_SECTION in prompt
        assert PEERINGDB_UNAVAILABLE not in prompt

    def test_peeringdb_unavailable_message_when_not_available(self):
        """Test peeringdb unavailable message when not available."""
        builder = PromptBuilder()
        prompt = builder.build(AvailableTools(peeringdb=False))

        assert PEERINGDB_UNAVAILABLE in prompt
        assert PEERINGDB_SECTION not in prompt

    def test_all_tools_available_includes_all_sections(self):
        """Test that all sections are included when all tools available."""
        builder = PromptBuilder()
        available = AvailableTools(
            bgp_radar=True,
            globalping=True,
            peeringdb=True,
            monocle=True,
        )
        prompt = builder.build(available)

        # All available sections should be present
        assert MONOCLE_SECTION in prompt
        assert BGP_RADAR_SECTION in prompt
        assert GLOBALPING_SECTION in prompt
        assert PEERINGDB_SECTION in prompt

        # No unavailable messages should be present
        assert MONOCLE_UNAVAILABLE not in prompt
        assert BGP_RADAR_UNAVAILABLE not in prompt
        assert GLOBALPING_UNAVAILABLE not in prompt
        assert PEERINGDB_UNAVAILABLE not in prompt

    def test_no_tools_available_includes_all_unavailable_messages(self):
        """Test that all unavailable messages included when no tools available."""
        builder = PromptBuilder()
        prompt = builder.build(AvailableTools())

        # All unavailable messages should be present
        assert MONOCLE_UNAVAILABLE in prompt
        assert BGP_RADAR_UNAVAILABLE in prompt
        assert GLOBALPING_UNAVAILABLE in prompt
        assert PEERINGDB_UNAVAILABLE in prompt

        # No available sections should be present
        assert MONOCLE_SECTION not in prompt
        assert BGP_RADAR_SECTION not in prompt
        assert GLOBALPING_SECTION not in prompt
        assert PEERINGDB_SECTION not in prompt

    def test_token_estimate_reasonable_all_tools(self):
        """Test token estimate is reasonable with all tools available."""
        builder = PromptBuilder()
        available = AvailableTools(
            bgp_radar=True,
            globalping=True,
            peeringdb=True,
            monocle=True,
        )
        prompt = builder.build(available)
        tokens = builder.estimate_tokens(prompt)

        # With all tools, should be under 1000 tokens (target: 425-750)
        assert tokens < 1000, f"Token estimate {tokens} exceeds 1000"
        # Should be at least 300 tokens (core prompt + sections)
        assert tokens > 300, f"Token estimate {tokens} is suspiciously low"

    def test_token_estimate_reasonable_no_tools(self):
        """Test token estimate is reasonable with no tools available."""
        builder = PromptBuilder()
        prompt = builder.build(AvailableTools())
        tokens = builder.estimate_tokens(prompt)

        # With unavailable messages, should still be under 800 tokens
        assert tokens < 800, f"Token estimate {tokens} exceeds 800"
        # Should be at least 200 tokens (core prompt + unavailable messages)
        assert tokens > 200, f"Token estimate {tokens} is suspiciously low"

    def test_prompt_contains_critical_guidance(self):
        """Test that prompt contains critical behavioral guidance."""
        builder = PromptBuilder()
        prompt = builder.build(AvailableTools(monocle=True))

        # Core behavioral requirements
        assert "ALWAYS USE TOOLS" in prompt
        assert "search_asn" in prompt
        assert "NEVER" in prompt  # Never answer from training data

    def test_prompt_mentions_peer_count_guidance_when_monocle_available(self):
        """Test that monocle section mentions peer count guidance."""
        builder = PromptBuilder()
        prompt = builder.build(AvailableTools(monocle=True))

        # Should mention peer count tools
        assert "get_as_peers" in prompt
        assert "get_as_connectivity_summary" in prompt
        # Should warn about path analysis not being peer count
        assert "PATH DIVERSITY" in prompt or "path diversity" in prompt.lower()


class TestPromptBuilderTokenEstimate:
    """Tests specifically for token estimation."""

    def test_estimate_tokens_empty_string(self):
        """Test token estimate for empty string."""
        builder = PromptBuilder()
        assert builder.estimate_tokens("") == 0

    def test_estimate_tokens_short_string(self):
        """Test token estimate for short string."""
        builder = PromptBuilder()
        # "Hello" = 5 chars, ~1 token
        tokens = builder.estimate_tokens("Hello")
        assert tokens == 1

    def test_estimate_tokens_longer_string(self):
        """Test token estimate for longer string."""
        builder = PromptBuilder()
        # 100 chars should be ~25 tokens
        text = "a" * 100
        tokens = builder.estimate_tokens(text)
        assert tokens == 25


class TestSecurityAndIPv6Awareness:
    """Tests for security-first methodology and IPv4/IPv6 awareness."""

    def test_security_first_methodology_in_core_prompt(self):
        """Test that core prompt contains security-first methodology."""
        builder = PromptBuilder()
        prompt = builder.build(AvailableTools())

        # Should contain security methodology section
        assert "SECURITY-FIRST METHODOLOGY" in prompt
        assert "RPKI" in prompt
        assert "get_rpki_status" in prompt or "check_prefix_anomalies" in prompt

    def test_rpki_guidance_included(self):
        """Test that RPKI validation guidance is included."""
        builder = PromptBuilder()
        prompt = builder.build(AvailableTools())

        # Should explain RPKI status meanings
        assert "invalid" in prompt.lower()
        assert "valid" in prompt.lower()
        assert "not-found" in prompt.lower() or "not found" in prompt.lower()

    def test_ipv4_ipv6_awareness_in_core_prompt(self):
        """Test that IPv4/IPv6 awareness guidance is included."""
        builder = PromptBuilder()
        prompt = builder.build(AvailableTools())

        # Should contain IPv4/IPv6 awareness section
        assert "IPv4/IPv6 AWARENESS" in prompt or "IPv4" in prompt
        assert "IPv6" in prompt
        assert "address family" in prompt.lower() or "separately" in prompt.lower()

    def test_monocle_section_mentions_ipv4_ipv6(self):
        """Test that monocle section mentions IPv4/IPv6 for prefix breakdown."""
        builder = PromptBuilder()
        prompt = builder.build(AvailableTools(monocle=True))

        # Should mention that AS relationships are address-family agnostic
        # and point to get_asn_announcements for IPv4/IPv6 breakdown
        assert "get_asn_announcements" in prompt
        assert "address-family" in prompt.lower() or "ipv4" in prompt.lower()

    def test_moas_guidance_included(self):
        """Test that MOAS (Multiple Origin AS) guidance is included."""
        builder = PromptBuilder()
        prompt = builder.build(AvailableTools())

        # Should mention MOAS can be legitimate
        assert "MOAS" in prompt or "multiple origin" in prompt.lower()

    def test_noc_contact_recommendation_for_invalid_rpki(self):
        """Test that NOC contact is recommended for RPKI invalid."""
        builder = PromptBuilder()
        prompt = builder.build(AvailableTools())

        # Should recommend contacting NOC for potential hijacks
        assert "NOC" in prompt or "contact" in prompt.lower()


class TestPromptBuilderIntegration:
    """Integration tests for prompt builder with realistic scenarios."""

    def test_typical_production_config(self):
        """Test typical production configuration with monocle required."""
        builder = PromptBuilder()
        # Typical config: monocle required, others optional
        available = AvailableTools(
            bgp_radar=False,  # Often not installed
            globalping=True,  # Usually available
            peeringdb=True,  # Usually available
            monocle=True,  # Required
        )
        prompt = builder.build(available)

        # Should have monocle guidance
        assert MONOCLE_SECTION in prompt
        # Should have unavailable message for bgp-radar
        assert BGP_RADAR_UNAVAILABLE in prompt
        # Should have available sections for others
        assert GLOBALPING_SECTION in prompt
        assert PEERINGDB_SECTION in prompt

    def test_minimal_config(self):
        """Test minimal configuration with only monocle."""
        builder = PromptBuilder()
        available = AvailableTools(monocle=True)
        prompt = builder.build(available)

        # Should have monocle but unavailable messages for others
        assert MONOCLE_SECTION in prompt
        assert BGP_RADAR_UNAVAILABLE in prompt
        assert GLOBALPING_UNAVAILABLE in prompt
        assert PEERINGDB_UNAVAILABLE in prompt

        # Token count should be reasonable
        tokens = builder.estimate_tokens(prompt)
        assert tokens < 800
