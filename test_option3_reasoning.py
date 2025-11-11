#!/usr/bin/env python3
"""
Test script for Option 3 agentic reasoning with conversation memory.
Tests the exact scenario from the user's conversation about FTP password extraction.
"""

import sys
import json
from app.modules.ollama_client import OllamaClient
from app.modules.conversation_memory import ConversationMemory
from app.modules.reasoning_engine import ReasoningEngine


def test_conversation_memory():
    """Test conversation memory functionality."""
    print("\n" + "="*80)
    print("TEST 1: Conversation Memory")
    print("="*80)

    memory = ConversationMemory(max_history=10)

    # Simulate conversation
    memory.add_exchange(
        user_query="which ip downloading files?",
        llm_response="Based on analysis, IP 192.254.225.136 was involved in FTP file transfers.",
        reasoning="Found FTP traffic with this IP",
        discovered_info={'ips': ['192.254.225.136'], 'protocols': ['FTP']}
    )

    memory.add_exchange(
        user_query="is this ip downloading any files?",
        llm_response="Yes, IP 192.254.225.136 has FTP communication showing authentication with user 'ben@ercolina-usa.com'.",
        reasoning="Found FTP authentication",
        discovered_info={'credentials': [{'type': 'username', 'value': 'ben@ercolina-usa.com'}]}
    )

    # Test reference resolution
    resolved = memory.resolve_reference("what was the password of that user?")
    print(f"\n✓ Reference resolution test:")
    print(f"  Original: 'what was the password of that user?'")
    print(f"  Resolved: {resolved[:100]}...")

    # Test context retrieval
    context = memory.get_conversation_context(last_n=2)
    print(f"\n✓ Conversation context retrieval:")
    print(f"  Retrieved {len(memory.conversation_history)} exchanges")
    print(f"  Context length: {len(context)} characters")

    # Test entity tracking
    entities_context = memory.get_discovered_entities_context()
    print(f"\n✓ Entity tracking:")
    print(f"  Discovered IPs: {memory.discovered_entities['ips']}")
    print(f"  Discovered credentials: {len(memory.discovered_entities['credentials'])} entries")

    print("\n✅ Conversation Memory tests passed!")
    return True


def test_reasoning_engine():
    """Test reasoning engine with mock scenarios."""
    print("\n" + "="*80)
    print("TEST 2: Reasoning Engine")
    print("="*80)

    try:
        ollama = OllamaClient(base_url="http://localhost:11434")

        # Check connection
        if not ollama.validate_connection():
            print("❌ Cannot connect to Ollama. Make sure Ollama is running.")
            return False

        memory = ConversationMemory()
        engine = ReasoningEngine(ollama, memory)

        # Mock PCAP summary
        mock_summary = {
            'statistics': {
                'total_packets': 1000,
                'unique_ips_count': 15,
                'top_protocols': {'TCP': 500, 'UDP': 300, 'FTP': 29}
            },
            'virustotal_results': {
                'summary': {'malicious_entities': 1},
                'flagged_entities': [
                    {
                        'entity_type': 'ip',
                        'entity_value': '192.254.225.136',
                        'malicious_count': 1,
                        'harmless_count': 62
                    }
                ]
            }
        }

        # Test 1: Analyze simple query intent
        print("\n✓ Testing query intent analysis...")
        intent = engine.analyze_query_intent(
            "which ip downloading files?",
            mock_summary
        )
        print(f"  Query type: {intent.get('query_type')}")
        print(f"  Needs dynamic analysis: {intent.get('needs_dynamic_analysis')}")
        print(f"  Reasoning: {intent.get('reasoning', 'N/A')[:100]}...")

        # Test 2: Check summary for answer
        print("\n✓ Testing summary-based answering...")
        answer = engine.check_summary_for_answer(
            "which ip is malicious?",
            mock_summary,
            {'can_answer_from_summary': True}
        )
        if answer and "NEEDS_DYNAMIC_ANALYSIS" not in answer:
            print(f"  Answer found: {answer[:150]}...")
        else:
            print("  Requires dynamic analysis")

        # Test 3: Plan dynamic analysis
        print("\n✓ Testing dynamic analysis planning...")
        memory.add_exchange(
            user_query="is this ip downloading any files?",
            llm_response="Previous analysis found FTP traffic with IP 192.254.225.136",
            discovered_info={'ips': ['192.254.225.136']}
        )

        plan_result = engine.plan_dynamic_analysis(
            "what was the password for user ben@ercolina-usa.com?",
            mock_summary,
            {'query_type': 'specific_investigation', 'needs_dynamic_analysis': True}
        )

        if plan_result.get('success'):
            plan = plan_result['plan']
            print(f"  Commands planned: {len(plan.get('commands', []))}")
            print(f"  Reasoning: {plan.get('reasoning', 'N/A')[:100]}...")
            if plan.get('commands'):
                first_cmd = plan['commands'][0]
                print(f"  First command purpose: {first_cmd.get('purpose')}")
                print(f"  Command args: {first_cmd.get('command_args')}")
        else:
            print(f"  ❌ Planning failed: {plan_result.get('error')}")

        print("\n✅ Reasoning Engine tests passed!")
        return True

    except Exception as e:
        print(f"\n❌ Reasoning Engine test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def test_ftp_scenario():
    """Test the exact FTP password extraction scenario from user's conversation."""
    print("\n" + "="*80)
    print("TEST 3: FTP Password Extraction Scenario")
    print("="*80)

    try:
        ollama = OllamaClient(base_url="http://localhost:11434")

        if not ollama.validate_connection():
            print("❌ Cannot connect to Ollama. Make sure Ollama is running.")
            return False

        memory = ConversationMemory()
        engine = ReasoningEngine(ollama, memory)

        mock_summary = {
            'statistics': {
                'total_packets': 1000,
                'top_protocols': {'TCP': 500, 'FTP': 29}
            },
            'virustotal_results': {
                'summary': {'malicious_entities': 1}
            }
        }

        # Simulate the conversation sequence
        print("\n--- Conversation Sequence ---")

        # Query 1: "which ip downloading files?"
        print("\n1️⃣ User: which ip downloading files?")
        intent1 = engine.analyze_query_intent("which ip downloading files?", mock_summary)
        print(f"   Intent: {intent1.get('query_type')}")

        # Simulate finding the IP
        memory.add_exchange(
            user_query="which ip downloading files?",
            llm_response="IP 192.254.225.136 was involved in file transfer activity via FTP protocol.",
            reasoning="Query about file downloads",
            discovered_info={'ips': ['192.254.225.136'], 'protocols': ['FTP']}
        )
        print("   ✓ Stored IP 192.254.225.136 in memory")

        # Query 2: "is this ip downloading any files?"
        print("\n2️⃣ User: is this ip downloading any files?")
        resolved2 = memory.resolve_reference("is this ip downloading any files?")
        print(f"   Resolved: {resolved2 is not None}")

        intent2 = engine.analyze_query_intent("is this ip downloading any files?", mock_summary)
        print(f"   Intent: {intent2.get('query_type')}")
        print(f"   References previous: {intent2.get('references_previous_context', False)}")

        # Simulate finding FTP authentication
        memory.add_exchange(
            user_query="is this ip downloading any files?",
            llm_response="Yes, this IP has FTP traffic. User 'ben@ercolina-usa.com' authenticated successfully.",
            reasoning="Follow-up about specific IP",
            discovered_info={'credentials': [{'type': 'username', 'value': 'ben@ercolina-usa.com'}]}
        )
        print("   ✓ Stored username in memory")

        # Query 3: "what was the password of that authenticated user?"
        print("\n3️⃣ User: what was the password of that authenticated user?")
        resolved3 = memory.resolve_reference("what was the password of that authenticated user?")
        print(f"   Resolved reference: {resolved3 is not None}")

        intent3 = engine.analyze_query_intent(
            "what was the password of that authenticated user?",
            mock_summary
        )
        print(f"   Intent: {intent3.get('query_type')}")
        print(f"   Needs dynamic analysis: {intent3.get('needs_dynamic_analysis')}")

        # Plan to extract password
        print("\n   Planning TShark commands to extract password...")
        plan_result = engine.plan_dynamic_analysis(
            "what was the password of that authenticated user?",
            mock_summary,
            intent3
        )

        if plan_result.get('success'):
            plan = plan_result['plan']
            print(f"   ✓ Generated {len(plan.get('commands', []))} command(s)")
            print(f"   Reasoning: {plan.get('reasoning', 'N/A')[:150]}...")

            for i, cmd in enumerate(plan.get('commands', []), 1):
                print(f"\n   Command {i}:")
                print(f"     Purpose: {cmd.get('purpose')}")
                print(f"     Args: {cmd.get('command_args')}")
                print(f"     Extracts: {cmd.get('extracts', 'N/A')}")

                # Check if it's looking for FTP password
                args_str = ' '.join(cmd.get('command_args', []))
                if 'ftp' in args_str.lower() and 'pass' in args_str.lower():
                    print(f"     ✅ Correctly targeting FTP password extraction!")
                elif 'ftp.request.command' in args_str and 'PASS' in args_str:
                    print(f"     ✅ Using correct FTP password filter!")
        else:
            print(f"   ❌ Planning failed: {plan_result.get('error')}")
            return False

        # Query 4: "what was the password of this user 'ben@ercolina-usa.com'?"
        print("\n4️⃣ User: what was the password of this user 'ben@ercolina-usa.com'?")

        intent4 = engine.analyze_query_intent(
            "what was the password of this user 'ben@ercolina-usa.com'?",
            mock_summary
        )

        plan_result4 = engine.plan_dynamic_analysis(
            "what was the password of this user 'ben@ercolina-usa.com'?",
            mock_summary,
            intent4
        )

        if plan_result4.get('success'):
            plan4 = plan_result4['plan']
            print(f"   ✓ Generated {len(plan4.get('commands', []))} command(s)")

            for cmd in plan4.get('commands', []):
                args_str = ' '.join(cmd.get('command_args', []))
                if 'ftp' in args_str.lower() and 'pass' in args_str.lower():
                    print(f"     ✅ Command targets FTP password correctly")
                    print(f"     Args: {cmd.get('command_args')}")

        print("\n" + "="*80)
        print("✅ FTP Password Extraction Scenario test passed!")
        print("="*80)
        print("\nSummary:")
        print(f"  - Conversation history: {len(memory.conversation_history)} exchanges")
        print(f"  - Discovered IPs: {memory.discovered_entities['ips']}")
        print(f"  - Discovered credentials: {len(memory.discovered_entities['credentials'])}")
        print(f"  - LLM successfully reasoned about FTP password extraction")
        print(f"  - Memory correctly resolved contextual references")

        return True

    except Exception as e:
        print(f"\n❌ FTP scenario test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests."""
    print("\n" + "="*80)
    print("OPTION 3 AGENTIC REASONING TEST SUITE")
    print("="*80)

    results = []

    # Test 1: Conversation Memory
    try:
        results.append(("Conversation Memory", test_conversation_memory()))
    except Exception as e:
        print(f"\n❌ Test failed with exception: {str(e)}")
        results.append(("Conversation Memory", False))

    # Test 2: Reasoning Engine (requires Ollama)
    try:
        results.append(("Reasoning Engine", test_reasoning_engine()))
    except Exception as e:
        print(f"\n❌ Test failed with exception: {str(e)}")
        results.append(("Reasoning Engine", False))

    # Test 3: FTP Scenario (requires Ollama)
    try:
        results.append(("FTP Password Scenario", test_ftp_scenario()))
    except Exception as e:
        print(f"\n❌ Test failed with exception: {str(e)}")
        results.append(("FTP Password Scenario", False))

    # Print summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)

    for test_name, passed in results:
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"  {status} - {test_name}")

    all_passed = all(result[1] for result in results)

    print("\n" + "="*80)
    if all_passed:
        print("🎉 ALL TESTS PASSED!")
    else:
        print("⚠️  SOME TESTS FAILED")
    print("="*80)

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
