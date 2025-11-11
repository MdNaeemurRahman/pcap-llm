from typing import Dict, Any, Optional, List
import json
from .ollama_client import OllamaClient
from .conversation_memory import ConversationMemory


class ReasoningEngine:
    """
    Multi-step reasoning engine for Option 3 agentic workflow.
    Handles query understanding, context analysis, and decision-making.
    """

    def __init__(self, ollama_client: OllamaClient, memory: ConversationMemory):
        self.ollama = ollama_client
        self.memory = memory

    def analyze_query_intent(
        self,
        user_query: str,
        pcap_summary: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Step 1: Analyze user query to understand intent and determine approach.
        Returns reasoning about what the user wants and how to get it.
        """
        conversation_context = self.memory.get_conversation_context(last_n=5)
        discovered_entities = self.memory.get_discovered_entities_context()

        resolved_query = self.memory.resolve_reference(user_query)
        if resolved_query:
            user_query = resolved_query

        prompt = f"""You are analyzing a user's query about network traffic to determine how to answer it.

{conversation_context}

{discovered_entities}

**PCAP SUMMARY CONTEXT:**
- Total packets: {pcap_summary.get('statistics', {}).get('total_packets', 'Unknown')}
- Protocols: {', '.join(list(pcap_summary.get('statistics', {}).get('top_protocols', {}).keys())[:5])}
- Malicious entities: {pcap_summary.get('virustotal_results', {}).get('summary', {}).get('malicious_entities', 0)}

**USER'S CURRENT QUERY:**
{user_query}

**YOUR TASK:**
Analyze this query and provide your reasoning in JSON format:

{{
  "query_type": "specific_investigation | overview | follow_up | greeting | command_request",
  "entities_mentioned": ["list of IPs, domains, users, etc mentioned"],
  "references_previous_context": true/false,
  "can_answer_from_summary": true/false,
  "needs_dynamic_analysis": true/false,
  "reasoning": "Brief explanation of what user wants",
  "approach": "how to answer: use summary data, execute tshark, check memory, etc"
}}

Respond ONLY with valid JSON."""

        try:
            response = self.ollama.generate_llm_response(
                prompt=prompt,
                stream=False,
                system_prompt="You are a query analysis expert. Respond only with valid JSON."
            )

            intent = self._parse_json_response(response)
            if not intent:
                intent = {
                    'query_type': 'specific_investigation',
                    'can_answer_from_summary': False,
                    'needs_dynamic_analysis': True,
                    'reasoning': 'Unable to parse intent, defaulting to dynamic analysis',
                    'approach': 'execute tshark commands'
                }

            return intent

        except Exception as e:
            print(f"[ReasoningEngine] Error in analyze_query_intent: {str(e)}")
            return {
                'query_type': 'specific_investigation',
                'can_answer_from_summary': False,
                'needs_dynamic_analysis': True,
                'reasoning': f'Error analyzing query: {str(e)}',
                'approach': 'execute tshark commands'
            }

    def check_summary_for_answer(
        self,
        user_query: str,
        pcap_summary: Dict[str, Any],
        intent: Dict[str, Any]
    ) -> Optional[str]:
        """
        Step 2: Check if query can be answered from summary data.
        Returns answer if available, None if dynamic analysis needed.
        """
        if not intent.get('can_answer_from_summary', False):
            return None

        conversation_context = self.memory.get_conversation_context(last_n=3)
        discovered_entities = self.memory.get_discovered_entities_context()

        summary_context = self._format_summary_context(pcap_summary)

        prompt = f"""You are a network security analyst. Answer the user's question using ONLY the summary data provided.

{conversation_context}

{discovered_entities}

**PCAP SUMMARY DATA:**
{summary_context}

**USER'S QUESTION:**
{user_query}

**INSTRUCTIONS:**
- Answer the question directly and concisely
- Use ONLY information from the summary above
- Cite specific evidence (IPs, packet counts, protocols)
- If the information is NOT in the summary, respond with exactly: "NEEDS_DYNAMIC_ANALYSIS"
- Be conversational and natural
- Match response length to question complexity (2-4 sentences for simple questions)

**YOUR ANSWER:**"""

        try:
            response = self.ollama.generate_llm_response(
                prompt=prompt,
                stream=False,
                system_prompt="You are a network security analyst. Be concise and cite evidence."
            )

            response = response.strip()

            if "NEEDS_DYNAMIC_ANALYSIS" in response:
                return None

            return response

        except Exception as e:
            print(f"[ReasoningEngine] Error checking summary: {str(e)}")
            return None

    def plan_dynamic_analysis(
        self,
        user_query: str,
        pcap_summary: Dict[str, Any],
        intent: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Step 3: Plan what TShark commands to execute based on reasoning.
        Returns detailed analysis plan with specific commands.
        """
        conversation_context = self.memory.get_conversation_context(last_n=5)
        discovered_entities = self.memory.get_discovered_entities_context()

        summary_brief = self._format_summary_brief(pcap_summary)

        prompt = f"""You are a TShark expert planning how to analyze a PCAP file to answer a user's question.

{conversation_context}

{discovered_entities}

**PCAP CONTEXT:**
{summary_brief}

**USER'S QUESTION:**
{user_query}

**QUERY ANALYSIS:**
{json.dumps(intent, indent=2)}

**YOUR TASK:**
Plan the TShark analysis needed. Think step-by-step about:
1. What specific information do we need to find?
2. What TShark filters will retrieve this information?
3. What protocol-specific fields should we extract?

**IMPORTANT TSHARK RULES:**
- Use -Y for display filters (NOT -f or -R)
- For FTP passwords: Use filter "ftp.request.command == PASS" and extract with -T fields -e ftp.request.arg
- For FTP users: Use filter "ftp.request.command == USER" and extract with -T fields -e ftp.request.arg
- For DNS queries: Use -T fields -e dns.qry.name -Y "dns.flags.response == 0"
- For HTTP downloads: Use -Y "http.request.method == GET" -T fields -e http.host -e http.request.uri
- For IP communications: Use -Y "ip.addr == X.X.X.X" to see all traffic
- For specific protocols: Use -Y "ftp" or -Y "http" or -Y "dns"
- Extract specific fields with: -T fields -e field1 -e field2

Respond with JSON:
{{
  "reasoning": "step-by-step thinking about what to analyze",
  "commands": [
    {{
      "command_args": ["-Y", "filter_here", "-T", "fields", "-e", "field"],
      "purpose": "what this command finds",
      "expected_output": "what we expect to see",
      "extracts": "what specific data this extracts (e.g., passwords, IPs, domains)"
    }}
  ],
  "interpretation_guidance": "how to interpret results"
}}

CRITICAL: Keep commands CONCISE. Generate MAX 3 commands. Respond ONLY with valid JSON."""

        try:
            response = self.ollama.generate_llm_response(
                prompt=prompt,
                stream=False,
                system_prompt="You are a TShark expert. Plan efficient analysis commands. Respond only with valid JSON."
            )

            plan = self._parse_json_response(response)

            if not plan or 'commands' not in plan:
                print(f"[ReasoningEngine] Failed to parse analysis plan")
                return {
                    'success': False,
                    'error': 'Failed to generate valid analysis plan'
                }

            return {
                'success': True,
                'plan': plan
            }

        except Exception as e:
            print(f"[ReasoningEngine] Error planning analysis: {str(e)}")
            return {
                'success': False,
                'error': f'Error planning analysis: {str(e)}'
            }

    def interpret_analysis_results(
        self,
        user_query: str,
        analysis_results: List[Dict[str, Any]],
        intent: Dict[str, Any]
    ) -> str:
        """
        Step 4: Interpret TShark command results and formulate natural response.
        Returns conversational answer based on findings.
        """
        conversation_context = self.memory.get_conversation_context(last_n=3)
        discovered_entities = self.memory.get_discovered_entities_context()

        results_summary = self._format_results_for_interpretation(analysis_results)

        prompt = f"""You are a network security analyst. A user asked you a question, you analyzed the network traffic, and now you need to explain your findings.

{conversation_context}

{discovered_entities}

**USER'S ORIGINAL QUESTION:**
{user_query}

**WHAT YOU DISCOVERED:**
{results_summary}

**YOUR TASK:**
Provide a natural, conversational response that:
1. Directly answers the user's question
2. Cites specific evidence you found (IPs, passwords, packet counts, timestamps)
3. Explains what the traffic shows and what it means
4. Is concise - match length to question complexity (2-4 sentences for simple questions)
5. NEVER mentions "commands", "tshark", "analysis", or technical execution details
6. Presents findings as if you personally analyzed the traffic

**RESPONSE STYLE:**
- Simple question about specific fact (password, IP, etc): 2-4 sentences with direct answer
- Investigation question: 1 paragraph explaining what you found
- Complex analysis: 2 paragraphs maximum

**CRITICAL:**
- If you found NO data/empty results, say: "I searched the network traffic but didn't find [what they asked for]. This could mean it's not present in this capture or may require different search parameters."
- DO NOT say "based on the command" or "the filter showed" - just state your findings naturally
- Be conversational like talking to a colleague

**YOUR RESPONSE:**"""

        try:
            response = self.ollama.generate_llm_response(
                prompt=prompt,
                stream=False,
                system_prompt="You are a conversational network security analyst. Be natural, concise, and cite evidence."
            )

            return response.strip()

        except Exception as e:
            print(f"[ReasoningEngine] Error interpreting results: {str(e)}")
            return "I encountered an issue interpreting the analysis results. Please try rephrasing your question."

    def extract_discovered_entities(
        self,
        analysis_results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Extract entities from analysis results for memory storage."""
        discovered = {
            'ips': [],
            'domains': [],
            'protocols': [],
            'credentials': [],
            'ports': []
        }

        for result in analysis_results:
            if not result.get('success'):
                continue

            output = result.get('output', '')
            purpose = result.get('purpose', '').lower()

            if 'password' in purpose or 'credential' in purpose:
                lines = str(output).strip().split('\n')
                for line in lines:
                    line = line.strip()
                    if line and len(line) < 100:
                        discovered['credentials'].append({
                            'type': 'password' if 'password' in purpose else 'credential',
                            'value': line,
                            'context': purpose
                        })

            if 'ip' in purpose or 'address' in purpose:
                import re
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                ips = re.findall(ip_pattern, str(output))
                discovered['ips'].extend(list(set(ips)))

            if 'domain' in purpose or 'dns' in purpose:
                lines = str(output).strip().split('\n')
                for line in lines:
                    line = line.strip()
                    if '.' in line and len(line) < 100 and ' ' not in line:
                        discovered['domains'].append(line)

        return discovered

    def _parse_json_response(self, response: str) -> Optional[Dict[str, Any]]:
        """Parse JSON from LLM response, handling markdown code blocks."""
        try:
            cleaned = response.strip()

            if cleaned.startswith('```json'):
                cleaned = cleaned[7:]
            elif cleaned.startswith('```'):
                cleaned = cleaned[3:]

            if cleaned.endswith('```'):
                cleaned = cleaned[:-3]

            cleaned = cleaned.strip()

            import re
            json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', cleaned, re.DOTALL)
            if json_match:
                cleaned = json_match.group()

            return json.loads(cleaned)

        except json.JSONDecodeError as e:
            print(f"[ReasoningEngine] JSON parse error: {str(e)}")
            print(f"[ReasoningEngine] Response was: {response[:500]}")
            return None
        except Exception as e:
            print(f"[ReasoningEngine] Unexpected error parsing JSON: {str(e)}")
            return None

    def _format_summary_context(self, pcap_summary: Dict[str, Any]) -> str:
        """Format PCAP summary for LLM context."""
        parts = []

        stats = pcap_summary.get('statistics', {})
        parts.append(f"Total Packets: {stats.get('total_packets', 'Unknown')}")
        parts.append(f"Unique IPs: {stats.get('unique_ips_count', 'Unknown')}")

        protocols = stats.get('top_protocols', {})
        if protocols:
            parts.append(f"Protocols: {', '.join([f'{k}({v})' for k, v in list(protocols.items())[:5]])}")

        vt_results = pcap_summary.get('virustotal_results', {})
        if vt_results:
            vt_summary = vt_results.get('summary', {})
            mal_count = vt_summary.get('malicious_entities', 0)
            if mal_count > 0:
                parts.append(f"\nMalicious entities detected: {mal_count}")

                flagged = vt_results.get('flagged_entities', [])
                mal_ips = [e['entity_value'] for e in flagged if e.get('entity_type') == 'ip' and e.get('malicious_count', 0) > 0]
                if mal_ips:
                    parts.append(f"Malicious IPs: {', '.join(mal_ips[:5])}")

        return '\n'.join(parts)

    def _format_summary_brief(self, pcap_summary: Dict[str, Any]) -> str:
        """Format brief summary for planning context."""
        stats = pcap_summary.get('statistics', {})
        return f"Total packets: {stats.get('total_packets', 'Unknown')}, Protocols: {', '.join(list(stats.get('top_protocols', {}).keys())[:5])}"

    def _format_results_for_interpretation(self, results: List[Dict[str, Any]]) -> str:
        """Format analysis results for LLM interpretation."""
        parts = []

        for i, result in enumerate(results, 1):
            parts.append(f"--- Analysis {i}: {result.get('purpose', 'Unknown')} ---")

            if result.get('success'):
                output = result.get('output', '')
                if output and str(output).strip():
                    output_preview = str(output)[:1500]
                    parts.append(f"Results found:\n{output_preview}")
                else:
                    parts.append("No matching data found")
            else:
                parts.append(f"Analysis failed: {result.get('output', 'Unknown error')}")

            parts.append("")

        return '\n'.join(parts)
