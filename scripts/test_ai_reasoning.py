#!/usr/bin/env python3
"""AI Reasoning & Consistency Test Suite for BGP Explorer.

Tests the AI's reasoning patterns and tool usage across 15 scenarios
with known expected outcomes. Generates a fix report for any failures.

Usage:
    uv run python scripts/test_ai_reasoning.py
    uv run python scripts/test_ai_reasoning.py --scenario 1.1  # Run single scenario
    uv run python scripts/test_ai_reasoning.py --category 1     # Run category
"""

import argparse
import asyncio
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from bgp_explorer.agent import BGPExplorerAgent
from bgp_explorer.ai.base import ChatEvent
from bgp_explorer.config import Settings
from bgp_explorer.output import OutputFormatter


@dataclass
class TestScenario:
    """Definition of a test scenario."""

    id: str
    query: str
    expected_tools: list[str]  # Tools that MUST be called
    pass_criteria: str
    category: str
    # Additional validation functions
    tool_order_matters: bool = False  # If True, tools must be called in order
    must_not_call: list[str] = field(default_factory=list)  # Tools that must NOT be called
    expect_clarification: bool = False  # Expects a clarification question, no tool calls


@dataclass
class TestResult:
    """Result of running a test scenario."""

    scenario: TestScenario
    passed: bool
    tool_calls: list[dict[str, Any]]
    response: str
    failure_reason: str | None = None
    execution_time: float = 0.0


# Define all 15 test scenarios
SCENARIOS = [
    # Category 1: Tool Usage Enforcement
    TestScenario(
        id="1.1",
        query="What is Google's ASN?",
        expected_tools=["search_asn"],
        pass_criteria="Calls search_asn BEFORE answering, doesn't say 'I know'",
        category="Tool Usage Enforcement",
    ),
    TestScenario(
        id="1.2",
        query="Who owns 8.8.8.0/24?",
        expected_tools=["lookup_prefix"],
        pass_criteria="Uses lookup_prefix, attributes answer to tool result",
        category="Tool Usage Enforcement",
    ),
    TestScenario(
        id="1.3",
        query="Is Cloudflare present at DE-CIX?",
        expected_tools=["search_asn", "get_ixps_for_asn"],
        pass_criteria="Verifies via tool, not from memory",
        category="Tool Usage Enforcement",
    ),
    # Category 2: Company Name Resolution
    TestScenario(
        id="2.1",
        query="Show me Google's announced prefixes",
        expected_tools=["search_asn"],  # Must search first; may ask for clarification if multiple ASNs
        pass_criteria="search_asn called FIRST; if multiple ASNs found, either asks for clarification OR proceeds with primary ASN",
        category="Company Name Resolution",
    ),
    TestScenario(
        id="2.2",
        query="What networks does Microsoft peer with?",
        expected_tools=["search_asn"],
        pass_criteria="If multiple ASNs found, asks for clarification",
        category="Company Name Resolution",
    ),
    # Category 3: Multi-Step Investigations
    TestScenario(
        id="3.1",
        query="Is 8.8.8.0/24 experiencing a hijack?",
        expected_tools=["lookup_prefix", "get_rpki_status"],
        pass_criteria="Uses 3+ tools, synthesizes findings",
        category="Multi-Step Investigations",
    ),
    TestScenario(
        id="3.2",
        query="Is Level3 (AS3356) providing transit to AS15169?",
        expected_tools=["check_as_relationship"],
        pass_criteria="Correctly interprets relationship type",
        category="Multi-Step Investigations",
    ),
    # Category 4: Clarification Handling
    TestScenario(
        id="4.1",
        query="lookup this prefix",
        expected_tools=[],
        pass_criteria="Asks 'which prefix?' - no tool calls first",
        category="Clarification Handling",
        expect_clarification=True,
    ),
    TestScenario(
        id="4.2",
        query="What upstreams does AS15169 have?",
        expected_tools=["get_as_upstreams"],
        pass_criteria="No unnecessary clarification, direct answer",
        category="Clarification Handling",
    ),
    # Category 5: Security Reasoning
    TestScenario(
        id="5.1",
        query="Check RPKI for 1.1.1.0/24 from AS13335",
        expected_tools=["get_rpki_status"],
        pass_criteria="Returns valid, explains security meaning",
        category="Security Reasoning",
    ),
    TestScenario(
        id="5.2",
        query="Is 8.8.8.0/24 being announced by AS64496 suspicious?",
        expected_tools=["get_rpki_status", "lookup_prefix"],
        pass_criteria="Flags as suspicious (wrong origin)",
        category="Security Reasoning",
    ),
    # Category 6: Relationship Interpretation
    TestScenario(
        id="6.1",
        query="Does AS15169 provide transit to other networks?",
        expected_tools=["get_as_downstreams"],
        pass_criteria="Uses downstreams (not mid-path count)",
        category="Relationship Interpretation",
    ),
    TestScenario(
        id="6.2",
        query="What is the relationship between AS174 and AS15169?",
        expected_tools=["check_as_relationship"],
        pass_criteria="Correctly identifies peer vs transit",
        category="Relationship Interpretation",
    ),
    # Category 7: Graceful Degradation
    TestScenario(
        id="7.1",
        query="Lookup prefix 192.0.2.0/24",
        expected_tools=["lookup_prefix"],
        pass_criteria="Explains no routes (documentation prefix), no crash",
        category="Graceful Degradation",
    ),
    TestScenario(
        id="7.2",
        query="Full analysis of AS99999",
        expected_tools=[],  # Will call tools but they'll return "not found"
        pass_criteria="Explains ASN doesn't exist, graceful response",
        category="Graceful Degradation",
    ),
]


class QuietOutputFormatter(OutputFormatter):
    """Minimal output formatter that suppresses most display."""

    def __init__(self):
        super().__init__()
        self._enabled = False

    def display_info(self, message: str) -> None:
        """Suppress info messages during tests."""
        pass

    def display_error(self, message: str) -> None:
        """Suppress error messages during tests."""
        pass

    def display_response(self, response: str) -> None:
        """Suppress response display during tests."""
        pass

    def display_bgp_event(self, event, monitoring_status: str | None = None) -> None:
        """Suppress BGP event display during tests."""
        pass


async def run_scenario(scenario: TestScenario, settings: Settings) -> TestResult:
    """Run a single test scenario and capture results.

    Args:
        scenario: The test scenario to run.
        settings: Application settings.

    Returns:
        TestResult with tool calls, response, and pass/fail status.
    """
    tool_calls: list[dict[str, Any]] = []

    def capture_events(event: ChatEvent) -> None:
        """Callback to capture tool calls from events."""
        if event.type == "tool_start" and event.data:
            tool_calls.append({
                "tool": event.data.get("tool"),
                "message": event.data.get("message"),
            })

    # Create agent with quiet output
    output = QuietOutputFormatter()
    agent = BGPExplorerAgent(settings, output)

    start_time = datetime.now()
    response = ""

    try:
        await agent.initialize()
        response = await agent.chat(scenario.query, on_event=capture_events)
    except Exception as e:
        return TestResult(
            scenario=scenario,
            passed=False,
            tool_calls=tool_calls,
            response=str(e),
            failure_reason=f"Exception during execution: {e}",
            execution_time=(datetime.now() - start_time).total_seconds(),
        )
    finally:
        await agent.shutdown()

    execution_time = (datetime.now() - start_time).total_seconds()

    # Evaluate pass/fail based on scenario criteria
    passed, failure_reason = evaluate_scenario(scenario, tool_calls, response)

    return TestResult(
        scenario=scenario,
        passed=passed,
        tool_calls=tool_calls,
        response=response,
        failure_reason=failure_reason,
        execution_time=execution_time,
    )


def evaluate_scenario(
    scenario: TestScenario,
    tool_calls: list[dict[str, Any]],
    response: str,
) -> tuple[bool, str | None]:
    """Evaluate whether a scenario passed based on its criteria.

    Args:
        scenario: The test scenario.
        tool_calls: List of tool calls made.
        response: The AI's response.

    Returns:
        Tuple of (passed, failure_reason).
    """
    tools_called = [tc["tool"] for tc in tool_calls]

    # Check for clarification scenarios (expect no tools before asking)
    if scenario.expect_clarification:
        if len(tool_calls) == 0:
            # Check if response contains a question
            question_indicators = ["?", "which", "what", "please specify", "could you"]
            has_question = any(ind in response.lower() for ind in question_indicators)
            if has_question:
                return True, None
            return False, "Expected clarification question but response doesn't ask anything"
        return False, f"Expected no tool calls before clarification, but called: {tools_called}"

    # Check required tools were called
    for expected_tool in scenario.expected_tools:
        if expected_tool not in tools_called:
            return False, f"Expected tool '{expected_tool}' was not called. Called: {tools_called}"

    # Check tool order if required
    if scenario.tool_order_matters and len(scenario.expected_tools) > 1:
        expected_order = scenario.expected_tools
        actual_order = [t for t in tools_called if t in expected_order]
        if actual_order != expected_order:
            return False, f"Tool order incorrect. Expected {expected_order}, got {actual_order}"

    # Check tools that must NOT be called
    for forbidden_tool in scenario.must_not_call:
        if forbidden_tool in tools_called:
            return False, f"Tool '{forbidden_tool}' was called but should not have been"

    # Scenario-specific validations
    if scenario.id == "1.1":
        # Must not use training data ("I know", "Google's ASN is")
        bad_phrases = ["i know", "google's asn is 15169", "google uses as15169"]
        for phrase in bad_phrases:
            if phrase in response.lower():
                return False, f"Used training data instead of tool: found '{phrase}'"

    elif scenario.id == "4.1":
        # Must ask for clarification
        if "prefix" not in response.lower() or "?" not in response:
            return False, "Did not ask for prefix clarification"

    elif scenario.id == "5.1":
        # Must explain RPKI validity
        if "valid" not in response.lower() and "rpki" not in response.lower():
            return False, "Did not explain RPKI validation result"

    elif scenario.id == "5.2":
        # Must flag as suspicious
        suspicious_indicators = ["suspicious", "invalid", "wrong", "not", "hijack", "mismatch"]
        if not any(ind in response.lower() for ind in suspicious_indicators):
            return False, "Did not flag the announcement as suspicious"

    elif scenario.id == "6.1":
        # Must use downstreams to determine transit
        if "get_as_downstreams" not in tools_called:
            return False, "Did not use get_as_downstreams to check transit capability"

    elif scenario.id == "7.1":
        # Must handle documentation prefix gracefully
        doc_indicators = ["no routes", "not announced", "documentation", "reserved", "rfc"]
        if not any(ind in response.lower() for ind in doc_indicators):
            return False, "Did not explain that 192.0.2.0/24 is a documentation prefix"

    elif scenario.id == "7.2":
        # Must handle non-existent ASN gracefully
        not_exist_indicators = [
            "not found", "doesn't exist", "does not exist", "no data", "invalid",
            "non-existent", "inactive", "no announcements", "not announcing",
            "not currently", "no visibility", "no prefixes"
        ]
        if not any(ind in response.lower() for ind in not_exist_indicators):
            return False, "Did not gracefully handle non-existent ASN"

    return True, None


def generate_report(
    results: list[TestResult],
    model: str = "sonnet",
    thinking_budget: int = 16000,
) -> str:
    """Generate markdown report from test results.

    Args:
        results: List of test results.
        model: The Claude model used for testing.
        thinking_budget: The thinking budget used for testing.

    Returns:
        Markdown formatted report string.
    """
    passed = sum(1 for r in results if r.passed)
    total = len(results)
    total_time = sum(r.execution_time for r in results)

    lines = [
        "# BGP Explorer AI Reasoning Test Report",
        "",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        f"**Model:** Claude {model.upper()}",
        "",
        f"**Thinking Budget:** {thinking_budget:,} tokens",
        "",
        "## Summary",
        "",
        f"**Result:** {passed}/{total} scenarios passed",
        "",
        f"**Pass Rate:** {passed/total*100:.1f}%",
        "",
        f"**Total Execution Time:** {total_time:.1f}s (avg {total_time/total:.1f}s per scenario)",
        "",
    ]

    # Group by category
    categories: dict[str, list[TestResult]] = {}
    for result in results:
        cat = result.scenario.category
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(result)

    lines.append("## Results by Category")
    lines.append("")

    for category, cat_results in categories.items():
        cat_passed = sum(1 for r in cat_results if r.passed)
        lines.append(f"### {category} ({cat_passed}/{len(cat_results)})")
        lines.append("")

        for result in cat_results:
            status = "PASS" if result.passed else "FAIL"
            lines.append(f"#### [{status}] Scenario {result.scenario.id}")
            lines.append("")
            lines.append(f"**Query:** `{result.scenario.query}`")
            lines.append("")
            lines.append(f"**Pass Criteria:** {result.scenario.pass_criteria}")
            lines.append("")
            lines.append(f"**Expected Tools:** {result.scenario.expected_tools or 'None (clarification expected)'}")
            lines.append("")
            lines.append(f"**Actual Tools Called:** {[tc['tool'] for tc in result.tool_calls]}")
            lines.append("")
            lines.append(f"**Execution Time:** {result.execution_time:.1f}s")
            lines.append("")

            if not result.passed:
                lines.append(f"**Failure Reason:** {result.failure_reason}")
                lines.append("")

            # Show response preview (first 500 chars)
            response_preview = result.response[:500]
            if len(result.response) > 500:
                response_preview += "..."
            lines.append("**Response Preview:**")
            lines.append("```")
            lines.append(response_preview)
            lines.append("```")
            lines.append("")

    # Failure Analysis section
    failures = [r for r in results if not r.passed]
    if failures:
        lines.append("## Failure Analysis & Fix Recommendations")
        lines.append("")

        for result in failures:
            lines.append(f"### Scenario {result.scenario.id}: {result.scenario.query[:50]}...")
            lines.append("")
            lines.append(f"**Category:** {result.scenario.category}")
            lines.append("")
            lines.append(f"**Issue:** {result.failure_reason}")
            lines.append("")

            # Generate specific fix recommendations
            fix = generate_fix_recommendation(result)
            lines.append("**Recommended Fix:**")
            lines.append("")
            lines.append(fix)
            lines.append("")

    else:
        lines.append("## All Tests Passed")
        lines.append("")
        lines.append("No failures detected. The AI reasoning patterns are working as expected.")
        lines.append("")

    return "\n".join(lines)


def generate_fix_recommendation(result: TestResult) -> str:
    """Generate a specific fix recommendation for a failed test.

    Args:
        result: The failed test result.

    Returns:
        Fix recommendation string.
    """
    scenario = result.scenario
    tools_called = [tc["tool"] for tc in result.tool_calls]

    if scenario.id == "1.1":
        if "search_asn" not in tools_called:
            return (
                "The AI is answering from training data instead of using tools.\n\n"
                "**Fix:** Strengthen the system prompt to emphasize that search_asn() MUST be called "
                "for any company name queries. Add negative examples showing what NOT to do."
            )

    if scenario.id == "2.1":
        if "search_asn" not in tools_called:
            return (
                "The AI is not resolving company names to ASNs before using ASN-specific tools.\n\n"
                "**Fix:** Add explicit instruction in system prompt: 'When a user mentions a company name "
                "(e.g., Google, Microsoft), you MUST call search_asn() FIRST before any other tool.'"
            )

    if scenario.id in ["4.1"]:
        return (
            "The AI is not asking for clarification when required information is missing.\n\n"
            "**Fix:** The system prompt should specify: 'When required parameters are missing "
            "(e.g., 'lookup this prefix' without specifying which prefix), ASK for clarification "
            "BEFORE calling any tools.'"
        )

    if scenario.id == "5.2":
        return (
            "The AI is not flagging suspicious announcements.\n\n"
            "**Fix:** Add security reasoning guidance: 'When checking if a prefix/origin pair is "
            "suspicious, verify the expected origin via lookup_prefix and compare with the claimed "
            "origin. Flag mismatches as potential hijacks.'"
        )

    if scenario.id == "6.1":
        return (
            "The AI is not using the correct tool to determine transit capability.\n\n"
            "**Fix:** Clarify in system prompt: 'To determine if an AS provides transit to other "
            "networks, use get_as_downstreams(). The 'mid-path transit' metric from get_asn_details() "
            "is NOT the correct measure for this.'"
        )

    if scenario.id in ["7.1", "7.2"]:
        return (
            "The AI is not gracefully handling edge cases.\n\n"
            "**Fix:** Add guidance for handling special cases:\n"
            "- Documentation prefixes (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)\n"
            "- Non-existent ASNs\n"
            "- Empty tool results\n\n"
            "The AI should explain what happened and not crash or give confusing responses."
        )

    # Generic recommendation
    return (
        f"The AI failed to meet the pass criteria: '{scenario.pass_criteria}'\n\n"
        f"**Tools expected:** {scenario.expected_tools}\n"
        f"**Tools called:** {tools_called}\n\n"
        "Review the system prompt and tool definitions to ensure the AI understands "
        "when and how to use each tool."
    )


async def main():
    """Main entry point for the test suite."""
    parser = argparse.ArgumentParser(description="AI Reasoning Test Suite")
    parser.add_argument("--scenario", help="Run specific scenario (e.g., 1.1)")
    parser.add_argument("--category", help="Run specific category (1-7)")
    parser.add_argument("--model", choices=["sonnet", "opus"], default="sonnet",
                       help="Claude model to use (default: sonnet) - both support extended thinking")
    parser.add_argument("--thinking-budget", type=int, default=16000,
                       help="Thinking budget in tokens (default: 16000)")
    parser.add_argument("--output", default="specs/ai-reasoning-test-report.md",
                       help="Output report path")
    args = parser.parse_args()

    # Filter scenarios if requested
    scenarios_to_run = SCENARIOS
    if args.scenario:
        scenarios_to_run = [s for s in SCENARIOS if s.id == args.scenario]
        if not scenarios_to_run:
            print(f"Scenario {args.scenario} not found")
            sys.exit(1)
    elif args.category:
        cat_num = args.category
        scenarios_to_run = [s for s in SCENARIOS if s.id.startswith(f"{cat_num}.")]
        if not scenarios_to_run:
            print(f"Category {cat_num} not found")
            sys.exit(1)

    # Load settings with model and thinking budget override
    from bgp_explorer.config import ClaudeModel
    model_map = {
        "sonnet": ClaudeModel.SONNET,
        "opus": ClaudeModel.OPUS,
    }
    settings = Settings(
        claude_model=model_map[args.model],
        thinking_budget=args.thinking_budget,
        max_tokens=max(args.thinking_budget + 16000, 32000),  # Ensure max_tokens > thinking_budget
    )

    print(f"Running {len(scenarios_to_run)} test scenario(s)")
    print(f"  Model: {args.model.upper()}")
    print(f"  Thinking Budget: {args.thinking_budget:,} tokens")
    print()

    results: list[TestResult] = []
    for i, scenario in enumerate(scenarios_to_run, 1):
        print(f"[{i}/{len(scenarios_to_run)}] Scenario {scenario.id}: {scenario.query[:50]}...")

        result = await run_scenario(scenario, settings)
        results.append(result)

        status = "PASS" if result.passed else "FAIL"
        print(f"         {status} ({result.execution_time:.1f}s)")
        if not result.passed:
            print(f"         Reason: {result.failure_reason}")
        print()

    # Generate report
    report = generate_report(results, model=args.model, thinking_budget=args.thinking_budget)

    # Ensure output directory exists
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Write report
    output_path.write_text(report)
    print(f"Report written to: {output_path}")

    # Summary
    passed = sum(1 for r in results if r.passed)
    print()
    print(f"=== SUMMARY: {passed}/{len(results)} passed ===")

    # Exit with error code if any failures
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    asyncio.run(main())
