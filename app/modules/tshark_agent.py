import json
import re
from typing import Dict, Any, List, Optional
from .ollama_client import OllamaClient
from .tshark_executor import TSharkExecutor


class TSharkAgent:
    def __init__(self, ollama_client: OllamaClient):
        self.ollama = ollama_client
        self.executor = TSharkExecutor()
        self.max_iterations = 5
        self.command_history = []

    def get_tshark_reference_prompt(self) -> str:
        return """You are an expert network security analyst with deep knowledge of TShark and Wireshark display filters.

**TSHARK COMMAND STRUCTURE:**
tshark -r <pcap_file> [options]

**IMPORTANT RULES:**
1. Always use display filters with -Y flag (NOT -f or -R for read filters)
2. You can only READ pcap files, never write or capture live
3. Keep commands focused and specific
4. Use appropriate output format: -T json, -T fields, or default text

**COMMON DISPLAY FILTER SYNTAX:**

IP and Network:
- ip.addr == 192.168.1.1 (traffic to or from IP)
- ip.src == 192.168.1.1 (source IP)
- ip.dst == 192.168.1.1 (destination IP)
- ip.addr == 10.0.0.0/24 (network range)

Ports and Protocols:
- tcp.port == 443 (TCP port)
- udp.port == 53 (UDP port)
- tcp.dstport == 80 (destination port)
- http (HTTP traffic)
- dns (DNS traffic)
- tls (TLS/SSL traffic)
- icmp (ICMP traffic)

DNS:
- dns.qry.name contains "google.com" (DNS query for domain)
- dns.qry.name == "example.com" (exact domain)
- dns.flags.response == 1 (DNS responses)

HTTP:
- http.request.method == "GET" (HTTP GET requests)
- http.host contains "example.com" (HTTP host)
- http.request.uri contains "/api" (URI path)
- http.response.code == 200 (HTTP status code)

TCP:
- tcp.flags.syn == 1 (SYN packets)
- tcp.flags.reset == 1 (RST packets)
- tcp.analysis.retransmission (retransmissions)

Combining Filters:
- Use && for AND: ip.addr == 192.168.1.1 && tcp.port == 443
- Use || for OR: http || dns
- Use ! for NOT: !icmp

**OUTPUT FORMATS:**
- Default text: Good for packet summaries
- -T json: JSON format for structured data
- -T fields -e field1 -e field2: Extract specific fields
- -q -z io,stat,0: Statistics
- -q -z io,phs: Protocol hierarchy

**FIELD EXTRACTION EXAMPLES:**
- -T fields -e ip.src -e ip.dst -e tcp.port
- -T fields -e dns.qry.name -e dns.a
- -T fields -e http.host -e http.request.uri

**EXAMPLE COMMANDS:**
1. All traffic to/from specific IP:
   -Y "ip.addr == 192.168.1.100"

2. DNS queries for a domain:
   -Y "dns.qry.name contains 'example.com'"

3. HTTP requests to specific host:
   -Y "http.host == 'api.example.com'"

4. Traffic on specific port:
   -Y "tcp.port == 443"

5. Extract IP communications as JSON:
   -Y "ip" -T json

6. Get DNS query names:
   -T fields -e dns.qry.name -Y "dns.flags.response == 0"

7. Find retransmissions:
   -Y "tcp.analysis.retransmission"

8. Protocol hierarchy statistics:
   -q -z io,phs

**YOUR TASK:**
When given a user query about a PCAP file, analyze what they're asking and generate the appropriate TShark command(s).
Return your response in JSON format with this structure:

{
  "reasoning": "Brief explanation of what you understand from the query",
  "commands": [
    {
      "command_args": ["list", "of", "tshark", "arguments"],
      "purpose": "What this command will find",
      "expected_output": "What kind of data this returns"
    }
  ],
  "needs_multiple_steps": false,
  "interpretation_guidance": "How to interpret the results for the user"
}

If the query is asking "what command should I run", provide the command but set a flag:
{
  "command_suggestion_only": true,
  "suggested_command": "tshark -r file.pcap -Y 'filter'",
  "explanation": "This command will..."
}

Be precise, security-focused, and helpful."""

    def analyze_query_and_generate_commands(
        self,
        user_query: str,
        pcap_summary: Dict[str, Any],
        pcap_file_path: str
    ) -> Dict[str, Any]:
        if not self.executor.is_available():
            return {
                'success': False,
                'error': 'TShark is not installed',
                'installation_instructions': self.executor.get_installation_instructions()
            }

        context = self._build_context(pcap_summary)

        if self._is_command_suggestion_request(user_query):
            return self._handle_command_suggestion(user_query, context)

        prompt = f"""{self.get_tshark_reference_prompt()}

**PCAP FILE CONTEXT:**
{context}

**USER QUERY:**
{user_query}

**YOUR RESPONSE:**
Analyze the query and provide TShark command(s) in JSON format as specified above.
Remember: Only use -Y for display filters, return JSON format response."""

        try:
            response = self.ollama.generate_llm_response(
                prompt=prompt,
                stream=False,
                system_prompt="You are a TShark expert. Always respond with valid JSON."
            )

            command_plan = self._parse_llm_response(response)

            if not command_plan:
                return {
                    'success': False,
                    'error': 'Failed to parse LLM response into command plan'
                }

            return {
                'success': True,
                'command_plan': command_plan,
                'llm_reasoning': command_plan.get('reasoning', '')
            }

        except Exception as e:
            return {
                'success': False,
                'error': f'Error generating commands: {str(e)}'
            }

    def execute_agentic_workflow(
        self,
        user_query: str,
        pcap_summary: Dict[str, Any],
        pcap_file_path: str
    ) -> Dict[str, Any]:
        self.command_history = []

        command_plan_result = self.analyze_query_and_generate_commands(
            user_query, pcap_summary, pcap_file_path
        )

        if not command_plan_result['success']:
            return command_plan_result

        command_plan = command_plan_result['command_plan']

        if command_plan.get('command_suggestion_only'):
            return {
                'success': True,
                'suggestion_only': True,
                'suggested_command': command_plan.get('suggested_command'),
                'explanation': command_plan.get('explanation')
            }

        commands = command_plan.get('commands', [])
        if not commands:
            return {
                'success': False,
                'error': 'No commands generated from query'
            }

        all_results = []
        for i, cmd_spec in enumerate(commands[:self.max_iterations]):
            print(f"Executing command {i+1}/{len(commands)}: {cmd_spec.get('purpose', 'N/A')}")

            result = self.executor.execute_custom_command(
                pcap_file_path,
                cmd_spec.get('command_args', [])
            )

            self.command_history.append({
                'command': result.get('command', ''),
                'purpose': cmd_spec.get('purpose', ''),
                'success': result['success']
            })

            all_results.append({
                'command': result.get('command', ''),
                'purpose': cmd_spec.get('purpose', ''),
                'output': result.get('output', result.get('error', '')),
                'success': result['success']
            })

            if not result['success']:
                break

        interpretation = self._interpret_results(
            user_query, all_results, command_plan.get('interpretation_guidance', '')
        )

        return {
            'success': True,
            'results': all_results,
            'interpretation': interpretation,
            'llm_reasoning': command_plan.get('reasoning', ''),
            'commands_executed': len(all_results)
        }

    def _build_context(self, pcap_summary: Dict[str, Any]) -> str:
        context_parts = []
        context_parts.append(f"Total Packets: {pcap_summary.get('statistics', {}).get('total_packets', 'Unknown')}")
        context_parts.append(f"Unique IPs: {pcap_summary.get('statistics', {}).get('unique_ips_count', 'Unknown')}")
        context_parts.append(f"Unique Domains: {pcap_summary.get('statistics', {}).get('unique_domains_count', 'Unknown')}")

        protocols = pcap_summary.get('statistics', {}).get('top_protocols', {})
        if protocols:
            context_parts.append(f"Top Protocols: {', '.join([f'{k}({v})' for k, v in list(protocols.items())[:5]])}")

        return '\n'.join(context_parts)

    def _is_command_suggestion_request(self, query: str) -> bool:
        suggestion_patterns = [
            'what command', 'which command', 'tshark command',
            'how do i', 'how to', 'what filter', 'show me the command'
        ]
        query_lower = query.lower()
        return any(pattern in query_lower for pattern in suggestion_patterns)

    def _handle_command_suggestion(self, user_query: str, context: str) -> Dict[str, Any]:
        prompt = f"""{self.get_tshark_reference_prompt()}

**PCAP CONTEXT:**
{context}

**USER REQUEST:**
{user_query}

The user is asking for a TShark command suggestion. Provide the command without executing it.
Return JSON with:
{{
  "command_suggestion_only": true,
  "suggested_command": "tshark -r file.pcap <your suggested arguments>",
  "explanation": "Detailed explanation of what this command does"
}}"""

        try:
            response = self.ollama.generate_llm_response(
                prompt=prompt,
                stream=False,
                system_prompt="You are a TShark expert. Provide command suggestions in JSON format."
            )

            return self._parse_llm_response(response)

        except Exception as e:
            return {
                'success': False,
                'error': f'Error generating command suggestion: {str(e)}'
            }

    def _parse_llm_response(self, response: str) -> Optional[Dict[str, Any]]:
        try:
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())

            return json.loads(response)
        except json.JSONDecodeError:
            print(f"Failed to parse LLM response as JSON: {response[:200]}")
            return None

    def _interpret_results(
        self,
        user_query: str,
        results: List[Dict[str, Any]],
        guidance: str
    ) -> str:
        results_summary = []
        for i, result in enumerate(results, 1):
            if result['success']:
                output_preview = result['output'][:500] if isinstance(result['output'], str) else str(result['output'])[:500]
                results_summary.append(f"Command {i}: {result['purpose']}\nOutput: {output_preview}")
            else:
                results_summary.append(f"Command {i}: {result['purpose']}\nError: {result['output']}")

        combined_results = '\n\n'.join(results_summary)

        prompt = f"""You are a network security analyst. A user asked: "{user_query}"

TShark commands were executed with these results:

{combined_results}

Guidance: {guidance}

Provide a clear, natural language explanation that:
1. Directly answers the user's question
2. Explains what was found in the PCAP file
3. Highlights any security-relevant findings
4. Provides context about what the data means

Be concise but thorough. Focus on insights, not just data."""

        try:
            interpretation = self.ollama.generate_llm_response(
                prompt=prompt,
                stream=False,
                system_prompt="You are a helpful network security analyst."
            )
            return interpretation
        except Exception as e:
            return f"Commands executed successfully. Raw output shown above. (Interpretation error: {str(e)})"
