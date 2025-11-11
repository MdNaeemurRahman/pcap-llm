import json
import re
from typing import Dict, Any, List, Optional
from pathlib import Path
from .ollama_client import OllamaClient
from .tshark_executor import TSharkExecutor
from .conversation_memory import ConversationMemory
from .reasoning_engine import ReasoningEngine


def sanitize_paths(text: str) -> str:
    """Remove absolute file paths and sensitive directory information from text."""
    if not text:
        return text

    # Replace common absolute path patterns
    text = re.sub(r'/[a-zA-Z0-9_\-./]+/data/uploads/[^\s]+\.pcap(?:ng)?', 'file.pcap', text)
    text = re.sub(r'C:\\[a-zA-Z0-9_\-\\]+\\[^\s]+\.pcap(?:ng)?', 'file.pcap', text)

    # Replace /usr/bin/tshark and similar with just 'tshark'
    text = re.sub(r'/usr/bin/tshark', 'tshark', text)
    text = re.sub(r'/usr/local/bin/tshark', 'tshark', text)

    # Replace absolute paths in general (Unix-style)
    text = re.sub(r'/[a-zA-Z0-9_\-./]+/[a-zA-Z0-9_\-./]+', '[path]', text)

    # Replace absolute paths (Windows-style)
    text = re.sub(r'[A-Z]:\\[a-zA-Z0-9_\-\\]+', '[path]', text)

    # Clean up 'tshark -r [path]' to 'tshark -r file.pcap'
    text = re.sub(r'tshark -r \[path\]', 'tshark -r file.pcap', text)

    return text


class TSharkAgent:
    def __init__(self, ollama_client: OllamaClient):
        self.ollama = ollama_client
        self.executor = TSharkExecutor()
        self.max_iterations = 5
        self.command_history = []
        self.memory = ConversationMemory(max_history=10)
        self.reasoning_engine = ReasoningEngine(ollama_client, self.memory)

    def _is_greeting(self, query: str) -> bool:
        """Check if the query is a simple greeting."""
        greetings = ['hi', 'hello', 'hey', 'good morning', 'good afternoon', 'good evening']
        query_lower = query.lower().strip()
        return any(greeting == query_lower or query_lower.startswith(greeting) for greeting in greetings) and len(query.split()) <= 3

    def _can_answer_from_summary(self, query: str, pcap_summary: Dict[str, Any], intent: Dict[str, Any]) -> Optional[str]:
        """Use reasoning engine to check if query can be answered from summary data."""
        return self.reasoning_engine.check_summary_for_answer(query, pcap_summary, intent)

    def get_tshark_reference_prompt(self) -> str:
        return """You are an expert network security analyst with deep knowledge of TShark and Wireshark display filters.

**CRITICAL JSON RESPONSE REQUIREMENTS:**
1. You MUST respond with COMPLETE, VALID JSON only
2. ALWAYS finish your JSON response - do NOT let it get cut off
3. Keep your response concise to avoid truncation
4. If you need to truncate, ALWAYS close all JSON structures properly
5. Test that your JSON is valid before responding

**TSHARK COMMAND STRUCTURE:**
tshark -r <pcap_file> [options]

**IMPORTANT RULES:**
1. Always use display filters with -Y flag (NOT -f or -R for read filters)
2. You can only READ pcap files, never write or capture live
3. Keep commands focused and specific (max 2-3 commands per response)
4. Use appropriate output format: -T json, -T fields, or default text
5. NEVER include the actual file path in command_args - the system provides it automatically
6. Keep command_args arrays SHORT and FOCUSED

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

FTP (File Transfer Protocol):
- ftp (all FTP traffic)
- ftp.request.command == "USER" (FTP username)
- ftp.request.command == "PASS" (FTP password)
- ftp.request.command == "RETR" (file download)
- ftp.request.command == "STOR" (file upload)
- ftp.request.arg (extract FTP command argument)
- ftp.response.code (FTP response codes)

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

7. Extract FTP passwords:
   -T fields -e ftp.request.arg -Y "ftp.request.command == PASS"

8. Extract FTP usernames:
   -T fields -e ftp.request.arg -Y "ftp.request.command == USER"

9. Find FTP file downloads:
   -T fields -e ftp.request.arg -Y "ftp.request.command == RETR"

10. See all FTP communication:
   -Y "ftp"

11. Find retransmissions:
   -Y "tcp.analysis.retransmission"

12. Protocol hierarchy statistics:
   -q -z io,phs

**YOUR TASK:**
When given a user query about a PCAP file, analyze what they're asking and generate the appropriate TShark command(s).

**CRITICAL: Your ENTIRE response must be VALID, COMPLETE JSON. Nothing else.**

Return your response in this EXACT JSON structure:

{
  "reasoning": "Brief 1-2 sentence explanation",
  "commands": [
    {
      "command_args": ["-Y", "filter_here"],
      "purpose": "Short description",
      "expected_output": "Brief output description"
    }
  ],
  "needs_multiple_steps": false,
  "interpretation_guidance": "Brief guidance"
}

**CRITICAL COMMAND GENERATION RULES:**
- Do NOT include '-r' or the file path in command_args - the system adds it automatically
- command_args should be SHORT: ["-Y", "ip.addr == 192.168.1.1"]
- For statistics: ["-q", "-z", "io,stat,0"]
- For field extraction: ["-T", "fields", "-e", "field_name", "-Y", "filter"]
- Keep reasoning and guidance BRIEF (under 100 chars each)
- Generate MAX 2 commands to avoid truncation

**FOR COMMAND SUGGESTION QUERIES:**
If the query asks "what command should I run", use this structure:
{
  "command_suggestion_only": true,
  "suggested_command": "tshark -r file.pcap -Y 'filter'",
  "explanation": "Brief explanation of what this does"
}

**EXAMPLE VALID RESPONSES:**

Example 1 (Execution):
{
  "reasoning": "User wants traffic to/from specific IP",
  "commands": [{"command_args": ["-Y", "ip.addr == 192.168.1.1"], "purpose": "Find all packets with this IP", "expected_output": "Packet list"}],
  "needs_multiple_steps": false,
  "interpretation_guidance": "Show packet count and communication patterns"
}

Example 2 (Suggestion):
{
  "command_suggestion_only": true,
  "suggested_command": "tshark -r file.pcap -Y 'ip.addr == 192.168.1.1'",
  "explanation": "This displays all packets involving the specified IP address"
}

Be precise, security-focused, and ALWAYS complete your JSON response."""

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
            suggestion_result = self._handle_command_suggestion(user_query, context)
            # Ensure success key is present
            if 'success' not in suggestion_result:
                suggestion_result['success'] = True
            return suggestion_result

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
                system_prompt="You are a TShark expert. Always respond with valid, complete JSON."
            )

            command_plan = self._parse_llm_response(response)

            if not command_plan:
                print(f"[TShark Agent] Failed to parse LLM response. Raw response: {response[:500]}")
                return {
                    'success': False,
                    'error': 'Failed to parse LLM response into command plan. The AI response was malformed - please try rephrasing your question or asking something simpler.'
                }

            if not isinstance(command_plan, dict):
                return {
                    'success': False,
                    'error': f'Invalid response format received. Please try rephrasing your question.'
                }

            validation_error = self._validate_command_plan(command_plan)
            if validation_error:
                print(f"[TShark Agent] Command plan validation failed: {validation_error}")
                return {
                    'success': False,
                    'error': f'Invalid command plan: {validation_error}. Please try a simpler query.'
                }

            return {
                'success': True,
                'command_plan': command_plan,
                'llm_reasoning': command_plan.get('reasoning', '')
            }

        except Exception as e:
            print(f"[TShark Agent] Exception in analyze_query_and_generate_commands: {str(e)}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': f'Unable to generate analysis commands. Please try rephrasing your question or ask about something more specific.'
            }

    def execute_agentic_workflow(
        self,
        user_query: str,
        pcap_summary: Dict[str, Any],
        pcap_file_path: str
    ) -> Dict[str, Any]:
        """
        NEW AGENTIC WORKFLOW with multi-step reasoning and conversational memory.

        Steps:
        1. Analyze query intent using reasoning engine
        2. Check if answer exists in summary data or conversation memory
        3. If not, plan and execute dynamic TShark analysis
        4. Interpret results and extract discovered entities
        5. Store in conversation memory for future reference
        """
        self.command_history = []

        print(f"[Option 3] Processing query with agentic reasoning: {user_query}")

        # Handle simple greetings
        if self._is_greeting(user_query):
            stats = pcap_summary.get('statistics', {})
            vt_results = pcap_summary.get('virustotal_results', {})
            vt_summary = vt_results.get('summary', {}) if vt_results else {}

            greeting = "Hello! I'm your AI security analyst. I can help you investigate this PCAP file by running dynamic analysis on the network traffic.\n\n"
            greeting += f"**Quick Overview:**\n"
            greeting += f"- Total packets: {stats.get('total_packets', 'Unknown')}\n"
            greeting += f"- Unique IPs: {stats.get('unique_ips_count', 'Unknown')}\n"

            if vt_summary:
                mal_count = vt_summary.get('malicious_entities', 0)
                if mal_count > 0:
                    greeting += f"- ⚠️ {mal_count} malicious entities detected by VirusTotal\n"

            greeting += "\nWhat would you like to know about the captured packets?"

            self.memory.add_exchange(
                user_query=user_query,
                llm_response=greeting,
                reasoning="Greeting interaction"
            )

            return {
                'success': True,
                'is_greeting': True,
                'response': greeting
            }

        # STEP 1: Analyze query intent with reasoning engine
        print("[Option 3] Step 1: Analyzing query intent...")
        intent = self.reasoning_engine.analyze_query_intent(user_query, pcap_summary)
        print(f"[Option 3] Intent analysis: {json.dumps(intent, indent=2)}")

        # STEP 2: Try to answer from summary data using reasoning
        if intent.get('can_answer_from_summary', False):
            print("[Option 3] Step 2: Checking if summary data contains answer...")
            summary_response = self._can_answer_from_summary(user_query, pcap_summary, intent)

            if summary_response:
                print("[Option 3] Answer found in summary data")
                self.memory.add_exchange(
                    user_query=user_query,
                    llm_response=summary_response,
                    reasoning=intent.get('reasoning', 'Answered from summary')
                )

                return {
                    'success': True,
                    'response': summary_response,
                    'mode': 'option3',
                    'answered_from_summary': True
                }

        # STEP 3: Check if user is asking for command suggestion
        if intent.get('query_type') == 'command_request':
            print("[Option 3] User requesting command suggestion")
            command_plan_result = self.analyze_query_and_generate_commands(
                user_query, pcap_summary, pcap_file_path
            )

            if command_plan_result.get('success', False):
                command_plan = command_plan_result.get('command_plan', {})
                if command_plan.get('command_suggestion_only'):
                    suggested_cmd = sanitize_paths(command_plan.get('suggested_command', ''))
                    response_text = f"To see this yourself, run:\n\n```bash\n{suggested_cmd}\n```\n\n{command_plan.get('explanation', '')}"

                    self.memory.add_exchange(
                        user_query=user_query,
                        llm_response=response_text,
                        reasoning="Command suggestion provided"
                    )

                    return {
                        'success': True,
                        'suggestion_only': True,
                        'suggested_command': suggested_cmd,
                        'explanation': command_plan.get('explanation')
                    }

        # STEP 4: Plan dynamic analysis using reasoning engine
        print("[Option 3] Step 3: Planning dynamic TShark analysis...")
        analysis_plan_result = self.reasoning_engine.plan_dynamic_analysis(
            user_query, pcap_summary, intent
        )

        if not analysis_plan_result.get('success', False):
            error_msg = analysis_plan_result.get('error', 'Failed to plan analysis')
            self.memory.add_exchange(
                user_query=user_query,
                llm_response=error_msg,
                reasoning="Analysis planning failed"
            )
            return {
                'success': False,
                'error': error_msg
            }

        analysis_plan = analysis_plan_result['plan']
        commands = analysis_plan.get('commands', [])

        if not commands:
            error_msg = "I couldn't determine how to analyze the traffic for your question. Could you rephrase it or ask about something more specific?"
            self.memory.add_exchange(
                user_query=user_query,
                llm_response=error_msg,
                reasoning="No commands generated"
            )
            return {
                'success': False,
                'error': error_msg
            }

        print(f"[Option 3] Planned {len(commands)} analysis commands")

        # STEP 5: Execute TShark commands
        print("[Option 3] Step 4: Executing TShark commands...")
        all_results = []
        for i, cmd_spec in enumerate(commands[:self.max_iterations]):
            print(f"[Option 3] Executing command {i+1}/{len(commands)}: {cmd_spec.get('purpose', 'N/A')}")

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
                'success': result['success'],
                'extracts': cmd_spec.get('extracts', '')
            })

            if not result['success']:
                print(f"[Option 3] Command {i+1} failed, stopping execution")
                break

        # STEP 6: Interpret results using reasoning engine
        print("[Option 3] Step 5: Interpreting analysis results...")
        interpretation = self.reasoning_engine.interpret_analysis_results(
            user_query, all_results, intent
        )

        # Sanitize interpretation to remove any leaked paths
        interpretation = sanitize_paths(interpretation)

        # STEP 7: Extract discovered entities and store in memory
        print("[Option 3] Step 6: Extracting discovered entities...")
        discovered_entities = self.reasoning_engine.extract_discovered_entities(all_results)

        self.memory.add_exchange(
            user_query=user_query,
            llm_response=interpretation,
            reasoning=analysis_plan.get('reasoning', ''),
            commands_executed=[{
                'command': sanitize_paths(r['command']),
                'purpose': r['purpose']
            } for r in all_results],
            discovered_info=discovered_entities
        )

        print(f"[Option 3] Workflow complete. Discovered entities: {list(discovered_entities.keys())}")

        # Sanitize commands in results for potential display
        sanitized_results = []
        for result in all_results:
            sanitized_result = result.copy()
            if 'command' in sanitized_result:
                sanitized_result['command'] = sanitize_paths(sanitized_result['command'])
            sanitized_results.append(sanitized_result)

        return {
            'success': True,
            'results': sanitized_results,
            'interpretation': interpretation,
            'llm_reasoning': analysis_plan.get('reasoning', ''),
            'commands_executed': len(all_results)
        }

    def _build_context(self, pcap_summary: Dict[str, Any]) -> str:
        context_parts = []

        context_parts.append("=== PCAP FILE SUMMARY ===")
        stats = pcap_summary.get('statistics', {})
        context_parts.append(f"Total Packets: {stats.get('total_packets', 'Unknown')}")
        context_parts.append(f"Unique IPs: {stats.get('unique_ips_count', 'Unknown')}")
        context_parts.append(f"Unique Domains: {stats.get('unique_domains_count', 'Unknown')}")

        protocols = stats.get('top_protocols', {})
        if protocols:
            context_parts.append(f"\nTop Protocols: {', '.join([f'{k}({v})' for k, v in list(protocols.items())[:5]])}")

        if 'virustotal_results' in pcap_summary:
            vt_summary = pcap_summary['virustotal_results'].get('summary', {})
            context_parts.append("\n=== THREAT INTELLIGENCE (VirusTotal) ===")
            context_parts.append(f"Total Entities Queried: {vt_summary.get('total_queried', 0)}")
            context_parts.append(f"Malicious Entities: {vt_summary.get('malicious_entities', 0)}")
            context_parts.append(f"Suspicious Entities: {vt_summary.get('suspicious_entities', 0)}")

            flagged_entities = pcap_summary['virustotal_results'].get('flagged_entities', [])
            if flagged_entities:
                malicious_ips = [e for e in flagged_entities if e.get('entity_type') == 'ip' and e.get('malicious_count', 0) > 0]
                malicious_domains = [e for e in flagged_entities if e.get('entity_type') == 'domain' and e.get('malicious_count', 0) > 0]
                malicious_files = [e for e in flagged_entities if e.get('entity_type') == 'file' and e.get('malicious_count', 0) > 0]

                if malicious_ips:
                    context_parts.append(f"\nMalicious IPs ({len(malicious_ips)}): {', '.join([e['entity_value'] for e in malicious_ips[:5]])}")
                if malicious_domains:
                    context_parts.append(f"Malicious Domains ({len(malicious_domains)}): {', '.join([e['entity_value'] for e in malicious_domains[:5]])}")
                if malicious_files:
                    context_parts.append(f"Malicious File Hashes ({len(malicious_files)}): {len(malicious_files)} detected")

        top_flows = pcap_summary.get('top_flows', {})
        if top_flows:
            context_parts.append(f"\n=== TOP NETWORK FLOWS ===")
            for flow, metadata in list(top_flows.items())[:5]:
                if isinstance(metadata, dict):
                    context_parts.append(f"{flow}: {metadata.get('packet_count', 0)} packets")
                else:
                    context_parts.append(f"{flow}: {metadata} packets")

        return '\n'.join(context_parts)

    def _is_command_suggestion_request(self, query: str) -> bool:
        suggestion_patterns = [
            'what command', 'which command', 'tshark command',
            'how do i', 'how to', 'what filter', 'show me the command',
            'what command can i run', 'which command should i run',
            'how can i run', 'command to see', 'tshark to see'
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

            parsed = self._parse_llm_response(response)

            if parsed is None:
                return {
                    'success': False,
                    'error': 'Failed to parse LLM response for command suggestion'
                }

            # Add success flag if not present
            if 'success' not in parsed:
                parsed['success'] = True

            return parsed

        except Exception as e:
            return {
                'success': False,
                'error': f'Error generating command suggestion: {str(e)}'
            }

    def _parse_llm_response(self, response: str) -> Optional[Dict[str, Any]]:
        try:
            cleaned_response = response.strip()
            if cleaned_response.startswith('```json'):
                cleaned_response = cleaned_response[7:]
            if cleaned_response.startswith('```'):
                cleaned_response = cleaned_response[3:]
            if cleaned_response.endswith('```'):
                cleaned_response = cleaned_response[:-3]
            cleaned_response = cleaned_response.strip()

            json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', cleaned_response, re.DOTALL)

            if json_match:
                json_str = json_match.group()
                json_str = self._fix_incomplete_json(json_str)
                parsed = json.loads(json_str)
            else:
                parsed = json.loads(cleaned_response)

            if not isinstance(parsed, dict):
                print(f"Parsed response is not a dictionary: {type(parsed)}")
                return None

            return parsed
        except json.JSONDecodeError as e:
            print(f"Failed to parse LLM response as JSON: {response[:600]}")
            print(f"JSON decode error: {str(e)}")
            return None
        except Exception as e:
            print(f"Unexpected error parsing LLM response: {str(e)}")
            return None

    def _fix_incomplete_json(self, json_str: str) -> str:
        quote_count = json_str.count('"') - json_str.count('\\"')

        if quote_count % 2 == 1:
            last_quote_pos = json_str.rfind('"')
            if last_quote_pos > 0:
                after_quote = json_str[last_quote_pos+1:].strip()
                if after_quote and not after_quote.startswith(']') and not after_quote.startswith('}'):
                    json_str = json_str[:last_quote_pos+1] + '"'

        open_brackets = json_str.count('[') - json_str.count('\\[')
        close_brackets = json_str.count(']') - json_str.count('\\]')

        if open_brackets > close_brackets:
            json_str += ']' * (open_brackets - close_brackets)

        open_braces = json_str.count('{') - json_str.count('\\{')
        close_braces = json_str.count('}') - json_str.count('\\}')

        if open_braces > close_braces:
            json_str += '}' * (open_braces - close_braces)

        return json_str

    def _validate_command_plan(self, command_plan: Dict[str, Any]) -> Optional[str]:
        if command_plan.get('command_suggestion_only'):
            if 'suggested_command' not in command_plan:
                return "Missing 'suggested_command' field in suggestion response"
            if not isinstance(command_plan['suggested_command'], str):
                return "Invalid 'suggested_command' field type"
            return None

        if 'commands' not in command_plan:
            return "Missing 'commands' field"

        commands = command_plan['commands']
        if not isinstance(commands, list):
            return "'commands' must be a list"

        if len(commands) == 0:
            return "Empty commands list"

        for i, cmd in enumerate(commands):
            if not isinstance(cmd, dict):
                return f"Command {i} is not a dictionary"

            if 'command_args' not in cmd:
                return f"Command {i} missing 'command_args' field"

            if not isinstance(cmd['command_args'], list):
                return f"Command {i} 'command_args' must be a list"

            if len(cmd['command_args']) == 0:
                return f"Command {i} has empty 'command_args'"

        return None

    def _interpret_results(
        self,
        user_query: str,
        results: List[Dict[str, Any]],
        guidance: str
    ) -> str:
        results_summary = []
        has_meaningful_results = False

        for i, result in enumerate(results, 1):
            if result['success']:
                output = result['output']
                output_preview = output[:1000] if isinstance(output, str) else str(output)[:1000]

                # Check if output is meaningful (not empty or just whitespace)
                if output and str(output).strip():
                    has_meaningful_results = True
                    results_summary.append(f"Analysis {i} - {result['purpose']}:\n{output_preview}")
                else:
                    results_summary.append(f"Analysis {i} - {result['purpose']}: No matching data found")
            else:
                results_summary.append(f"Analysis {i} failed: Unable to retrieve data for {result['purpose']}")

        combined_results = '\n\n'.join(results_summary)

        # If no meaningful results, provide a helpful fallback
        if not has_meaningful_results:
            return f"I searched the network traffic for information related to your query, but didn't find any matching data. This could mean:\n\n- The specific element you're looking for isn't present in this capture\n- The query might need to be more specific or use different terms\n- The traffic capture might not contain relevant activity\n\nTry asking about general statistics, overall threats, or rephrasing your question with different specifics."

        prompt = f"""You are an expert network security analyst. A user asked: "{user_query}"

You executed dynamic analysis on the PCAP file and gathered the following information:

{combined_results}

Guidance: {guidance}

**YOUR TASK:**
Provide a professional, conversational response that:
1. Directly answers the user's specific question
2. Explains what was discovered in clear, accessible language
3. Highlights security-relevant findings and their implications
4. Provides actionable context and recommendations when appropriate

**CRITICAL RESPONSE STYLE RULES:**
- Be conversational and natural, like talking to a colleague
- Match response length to question complexity:
  * Simple query ("find IP X") = 2-4 sentences
  * Moderate query = 1 paragraph (5-7 sentences)
  * Complex investigation = 2 paragraphs maximum
- Focus on INSIGHTS and ANALYSIS, not raw data dumps
- Use specific evidence (IPs, timestamps, packet counts) naturally in your explanation
- NEVER mention "commands", "tshark", "analysis steps", "filters", or technical execution details
- Present findings as if you directly analyzed the traffic yourself
- Avoid phrases like "based on the analysis" or "the results show" - just state your findings

**GOOD RESPONSE EXAMPLES:**

Example 1 (Simple query: "find communication session of this ip 192.254.225.136"):
"I found 247 packets involving IP 192.254.225.136 across 8 different communication sessions. This host primarily communicated with two external servers (203.0.113.45 and 198.51.100.78) using HTTPS on port 443. The connections occurred between 14:30 and 15:45 UTC, exchanging approximately 1.2 MB of data. This appears to be standard web application traffic with no immediate security concerns."

Example 2 (Command query: "what command can i run to see this output?"):
"To see this information yourself, you can run: `tshark -r file.pcap -Y 'ip.addr == 192.254.225.136'`. This filter will show all packets involving that specific IP address. If you want more detailed output, add `-T json` for structured data or `-T fields -e ip.src -e ip.dst` to extract specific fields."

**BAD RESPONSE EXAMPLES (DO NOT DO THIS):**
- "Based on the TShark command execution, Analysis 1 shows..."
- "The command output indicates that the filter returned..."
- "After running the display filter, the results show..."
- "The analysis executed successfully and found..."

Provide your analysis now:"""

        try:
            interpretation = self.ollama.generate_llm_response(
                prompt=prompt,
                stream=False,
                system_prompt=self.ollama.get_option3_system_prompt()
            )
            return interpretation
        except Exception as e:
            return f"Unable to complete analysis. Please try rephrasing your question or ask about different aspects of the network traffic."
