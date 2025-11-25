import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from .ollama_client import OllamaClient
from .vector_store import VectorStoreManager
from .supabase_client import SupabaseManager
from .query_classifier import QueryClassifier
from .tshark_agent import TSharkAgent

class ChatHandler:
    def __init__(
        self,
        ollama_client: OllamaClient,
        vector_store: VectorStoreManager,
        supabase_manager: SupabaseManager,
        json_outputs_dir: str
    ):
        self.ollama = ollama_client
        self.vector_store = vector_store
        self.supabase = supabase_manager
        self.json_outputs_dir = Path(json_outputs_dir)
        self.classifier = QueryClassifier()
        self.tshark_agent = TSharkAgent(ollama_client)
        self.option3_agents = {}
        self.option1_session_memory = {}

    def handle_option1_query(self, analysis_id: str, query: str) -> Dict[str, Any]:
        try:
            analysis = self.supabase.get_analysis_by_id(analysis_id)
            if not analysis:
                return {
                    'status': 'error',
                    'message': 'Analysis not found'
                }

            if analysis['status'] != 'ready':
                return {
                    'status': 'error',
                    'message': f"Analysis is not ready. Current status: {analysis['status']}"
                }

            summary_file = self.json_outputs_dir / f"{analysis_id}_summary_enriched.json"
            if not summary_file.exists():
                return {
                    'status': 'error',
                    'message': 'Summary file not found'
                }

            with open(summary_file, 'r') as f:
                summary_data = json.load(f)

            if analysis_id not in self.option1_session_memory:
                self.option1_session_memory[analysis_id] = {
                    'exchanges': [],
                    'entities_mentioned': {'ips': [], 'domains': [], 'files': []},
                    'vt_findings_shared': set()
                }

            session_memory = self.option1_session_memory[analysis_id]

            context = self._format_summary_context(summary_data)

            enriched_query = self._enrich_query_with_session_memory(query, session_memory)

            memory_context = self._format_session_memory_context(session_memory)

            prompt = self.ollama.format_prompt_for_network_analysis(
                query=enriched_query,
                context=context,
                chat_history=None,
                analysis_mode='option1',
                session_memory_context=memory_context
            )

            system_prompt = self.ollama.get_system_prompt()
            response = self.ollama.generate_llm_response(
                prompt=prompt,
                stream=False,
                system_prompt=system_prompt
            )

            self._update_session_memory(session_memory, query, response, summary_data)

            self.supabase.insert_chat_message(
                analysis_id=analysis_id,
                user_query=query,
                llm_response=response,
                retrieved_chunks=None
            )

            return {
                'status': 'success',
                'response': response,
                'mode': 'option1'
            }

        except Exception as e:
            print(f"Error in Option 1 query: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def handle_option2_query(self, analysis_id: str, query: str, top_k: int = 3) -> Dict[str, Any]:
        try:
            analysis = self.supabase.get_analysis_by_id(analysis_id)
            if not analysis:
                return {
                    'status': 'error',
                    'message': 'Analysis not found'
                }

            if analysis['status'] != 'ready':
                return {
                    'status': 'error',
                    'message': f"Analysis is not ready. Current status: {analysis['status']}"
                }

            if not self.vector_store.collection_exists(analysis_id):
                return {
                    'status': 'error',
                    'message': 'Vector collection not found for this analysis'
                }

            query_classification = self.classifier.classify_query(query)

            if query_classification['is_greeting']:
                response = self._handle_greeting_query(query)
                self.supabase.insert_chat_message(
                    analysis_id=analysis_id,
                    user_query=query,
                    llm_response=response,
                    retrieved_chunks=None
                )
                return {
                    'status': 'success',
                    'response': response,
                    'mode': 'option2',
                    'retrieved_chunks': None
                }

            if query_classification['is_help_request']:
                response = self._handle_help_query()
                self.supabase.insert_chat_message(
                    analysis_id=analysis_id,
                    user_query=query,
                    llm_response=response,
                    retrieved_chunks=None
                )
                return {
                    'status': 'success',
                    'response': response,
                    'mode': 'option2',
                    'retrieved_chunks': None
                }

            chat_history = self.supabase.get_chat_history(analysis_id)
            formatted_history = [
                {'user': msg['user_query'], 'assistant': msg['llm_response']}
                for msg in chat_history[-5:]
            ]

            enriched_query = self._enrich_query_with_context(query, formatted_history)
            expanded_query = self._expand_query(enriched_query, query_classification)

            # Use hybrid search for forensic queries, vector search for others
            if self._is_forensic_query(query):
                print(f"[Search Mode] Using HYBRID search for forensic query")
                print(f"Performing hybrid search with query: '{expanded_query}'")
                search_results = self.vector_store.hybrid_search(
                    collection_name=f"pcap_{analysis_id}",
                    query_text=expanded_query,
                    n_results=top_k,
                    alpha=0.4  # Favor BM25 for exact keyword matching (60% BM25, 40% vector)
                )
            else:
                print(f"[Search Mode] Using VECTOR search for general query")
                print(f"Performing similarity search with query: '{expanded_query}'")
                search_results = self.vector_store.similarity_search(
                    collection_name=f"pcap_{analysis_id}",
                    query_text=expanded_query,
                    n_results=top_k
                )

            if search_results['count'] == 0:
                print("No relevant chunks found, falling back to summary-based response")
                return self._handle_fallback_to_summary(analysis_id, query)

            # Pass query to enable forensic-specific threshold
            filtered_chunks = self._filter_chunks_by_relevance(search_results['chunks'], query=query)

            if len(filtered_chunks) == 0:
                print("All chunks filtered out due to low relevance")
                # Try direct JSON fallback for forensic queries before giving up
                if self._is_forensic_query(query):
                    print("[Fallback] Attempting direct JSON forensic data extraction...")
                    json_answer = self._direct_json_forensic_fallback(analysis_id, query)
                    if json_answer:
                        return json_answer
                print("Using summary fallback")
                return self._handle_fallback_to_summary(analysis_id, query)

            context = self._format_rag_context(filtered_chunks)

            prompt = self.ollama.format_prompt_for_option2_analysis(
                query=enriched_query,
                context=context,
                chat_history=formatted_history
            )

            system_prompt = self.ollama.get_option2_system_prompt()
            response = self.ollama.generate_llm_response(
                prompt=prompt,
                stream=False,
                system_prompt=system_prompt
            )

            retrieved_chunks_info = [
                {
                    'text': chunk['text'][:200],
                    'metadata': chunk['metadata'],
                    'distance': chunk['distance']
                }
                for chunk in filtered_chunks
            ]

            self.supabase.insert_chat_message(
                analysis_id=analysis_id,
                user_query=query,
                llm_response=response,
                retrieved_chunks=retrieved_chunks_info
            )

            return {
                'status': 'success',
                'response': response,
                'mode': 'option2',
                'retrieved_chunks': retrieved_chunks_info
            }

        except Exception as e:
            print(f"Error in Option 2 query: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def _get_or_create_option3_agent(self, analysis_id: str) -> TSharkAgent:
        """Get or create a TSharkAgent with persistent memory for this analysis session."""
        if analysis_id not in self.option3_agents:
            print(f"[Option 3] Creating new agent with conversation memory for analysis {analysis_id}")
            self.option3_agents[analysis_id] = TSharkAgent(self.ollama)
        return self.option3_agents[analysis_id]

    def clear_option3_memory(self, analysis_id: str):
        """Clear conversation memory for a specific analysis session."""
        if analysis_id in self.option3_agents:
            print(f"[Option 3] Clearing conversation memory for analysis {analysis_id}")
            del self.option3_agents[analysis_id]

    def clear_all_option3_memories(self):
        """Clear all Option 3 conversation memories (useful for memory management)."""
        print(f"[Option 3] Clearing all conversation memories ({len(self.option3_agents)} sessions)")
        self.option3_agents.clear()

    def handle_option3_query(self, analysis_id: str, query: str) -> Dict[str, Any]:
        try:
            analysis = self.supabase.get_analysis_by_id(analysis_id)
            if not analysis:
                return {
                    'status': 'error',
                    'message': 'Analysis not found'
                }

            if analysis['status'] != 'ready':
                return {
                    'status': 'error',
                    'message': f"Analysis is not ready. Current status: {analysis['status']}"
                }

            summary_file = self.json_outputs_dir / f"{analysis_id}_summary_enriched.json"
            if not summary_file.exists():
                return {
                    'status': 'error',
                    'message': 'Summary file not found'
                }

            with open(summary_file, 'r') as f:
                summary_data = json.load(f)

            pcap_file_path = self.supabase.get_pcap_file_path(analysis_id)
            if not pcap_file_path:
                return {
                    'status': 'error',
                    'message': 'PCAP file path not found in database. Cannot execute TShark commands.'
                }

            if not Path(pcap_file_path).exists():
                return {
                    'status': 'error',
                    'message': f'PCAP file not found at stored path: {pcap_file_path}'
                }

            # Get or create agent with persistent memory for this session
            agent = self._get_or_create_option3_agent(analysis_id)

            if not agent.executor.is_available():
                error_msg = agent.executor.get_installation_instructions()
                self.supabase.insert_chat_message(
                    analysis_id=analysis_id,
                    user_query=query,
                    llm_response=error_msg,
                    retrieved_chunks=None
                )
                return {
                    'status': 'error',
                    'message': error_msg,
                    'mode': 'option3'
                }

            print(f"[Option 3] Executing agentic workflow for query: {query}")
            print(f"[Option 3] Conversation history size: {len(agent.memory.conversation_history)}")
            result = agent.execute_agentic_workflow(
                user_query=query,
                pcap_summary=summary_data,
                pcap_file_path=pcap_file_path
            )

            # Validate result structure
            if not isinstance(result, dict):
                print(f"[Option 3] Unexpected result type: {type(result)}")
                return {
                    'status': 'error',
                    'message': 'Unexpected response format from analysis engine',
                    'mode': 'option3'
                }

            if not result.get('success', False):
                error_response = result.get('error', 'Unknown error occurred')
                self.supabase.insert_chat_message(
                    analysis_id=analysis_id,
                    user_query=query,
                    llm_response=error_response,
                    retrieved_chunks=None
                )
                return {
                    'status': 'error',
                    'message': error_response,
                    'mode': 'option3'
                }

            # Handle greeting responses
            if result.get('is_greeting'):
                response = result.get('response')
                self.supabase.insert_chat_message(
                    analysis_id=analysis_id,
                    user_query=query,
                    llm_response=response,
                    retrieved_chunks=None
                )
                return {
                    'status': 'success',
                    'response': response,
                    'mode': 'option3'
                }

            # Handle summary-based responses
            if result.get('answered_from_summary'):
                response = result.get('response')
                self.supabase.insert_chat_message(
                    analysis_id=analysis_id,
                    user_query=query,
                    llm_response=response,
                    retrieved_chunks={'source': 'summary_data'}
                )
                return {
                    'status': 'success',
                    'response': response,
                    'mode': 'option3',
                    'answered_from_summary': True
                }

            if result.get('suggestion_only'):
                response = f"**TShark Command Suggestion:**\n\n```bash\n{result['suggested_command']}\n```\n\n**Explanation:**\n{result['explanation']}"
                self.supabase.insert_chat_message(
                    analysis_id=analysis_id,
                    user_query=query,
                    llm_response=response,
                    retrieved_chunks=None
                )
                return {
                    'status': 'success',
                    'response': response,
                    'mode': 'option3',
                    'suggestion_only': True
                }

            commands_executed = result.get('results', [])
            interpretation = result.get('interpretation', '')
            reasoning = result.get('llm_reasoning', '')

            # Check if user is explicitly asking for command help
            is_command_query = any(phrase in query.lower() for phrase in [
                'what command', 'which command', 'tshark command', 'how do i run', 'show me command'
            ])

            response_parts = []

            # Add findings/interpretation as the main response
            if interpretation:
                response_parts.append(interpretation)

            # Only show command details if user explicitly asked for them
            if is_command_query and commands_executed:
                response_parts.append("\n\n**Command to run this analysis yourself:**")
                for i, cmd_result in enumerate(commands_executed, 1):
                    if i == 1:  # Only show first command as example
                        response_parts.append(f"```bash\n{cmd_result['command']}\n```")
                        break

            final_response = "\n".join(response_parts)

            tshark_metadata = {
                'commands_executed': [
                    {
                        'command': cmd['command'],
                        'purpose': cmd.get('purpose', ''),
                        'success': cmd.get('success', False)
                    }
                    for cmd in commands_executed
                ],
                'reasoning': reasoning
            }

            self.supabase.insert_chat_message(
                analysis_id=analysis_id,
                user_query=query,
                llm_response=final_response,
                retrieved_chunks=tshark_metadata
            )

            return {
                'status': 'success',
                'response': final_response,
                'mode': 'option3',
                'commands_executed': commands_executed,
                'reasoning': reasoning
            }

        except Exception as e:
            print(f"Error in Option 3 query: {str(e)}")
            import traceback
            traceback.print_exc()
            return {
                'status': 'error',
                'message': f'Error processing query: {str(e)}',
                'mode': 'option3'
            }

    def _format_summary_context(self, summary_data: Dict[str, Any]) -> str:
        """Format concise, security-focused summary for malware analysis."""
        context_parts = []

        # PRIORITY: Forensic Host Identification (if available)
        if summary_data.get('forensic_profile') and summary_data['forensic_profile'].get('infected_host'):
            host = summary_data['forensic_profile']['infected_host']
            context_parts.append("=== INFECTED HOST IDENTIFICATION ===")
            context_parts.append(f"IP Address: {host.get('ip', 'N/A')}")
            context_parts.append(f"MAC Address: {host.get('mac', 'N/A')}")
            context_parts.append(f"Hostname: {host.get('hostname', 'N/A')}")
            context_parts.append(f"User Account: {host.get('user_account', 'N/A')}")
            context_parts.append(f"Domain: {host.get('domain', 'N/A')}")
            context_parts.append(f"OS Version: {host.get('os_version', 'N/A')}")
            context_parts.append(f"First Activity: {host.get('first_seen', 'N/A')}")
            context_parts.append("")

        context_parts.append("=== PCAP SUMMARY ===")
        context_parts.append(f"File: {summary_data['file_info']['filename']}")
        context_parts.append(f"Packets: {summary_data['statistics']['total_packets']} | IPs: {summary_data['statistics']['unique_ips_count']} | Domains: {summary_data['statistics']['unique_domains_count']}")

        top_protocols = summary_data['statistics']['top_protocols']
        context_parts.append(f"Top Protocols: {', '.join([f'{k}({v})' for k, v in list(top_protocols.items())[:5]])}")

        timeline = self._extract_malware_timeline(summary_data)
        if timeline:
            context_parts.append(f"\n=== MALWARE BEHAVIOR TIMELINE ===")
            for event in timeline[:8]:
                context_parts.append(f"[{event['time']}] {event['description']}")

        if 'virustotal_results' in summary_data:
            vt_summary = summary_data['virustotal_results']['summary']
            mal_count = vt_summary.get('malicious_entities', 0)
            sus_count = vt_summary.get('suspicious_entities', 0)

            context_parts.append(f"\n=== THREAT INTELLIGENCE ===")
            context_parts.append(f"VirusTotal: {mal_count} malicious, {sus_count} suspicious")

            flagged = summary_data['virustotal_results']['flagged_entities']

            file_threats = [e for e in flagged if e.get('entity_type') == 'file' and e.get('malicious_count', 0) > 0]
            if file_threats:
                context_parts.append("\nMalicious Files:")
                for entity in file_threats[:3]:
                    mal = entity.get('malicious_count', 0)
                    total = mal + entity.get('harmless_count', 0)
                    label = entity.get('threat_label', 'Unknown')
                    context_parts.append(f"  Hash: {entity.get('entity_value', 'N/A')[:16]}... [{mal}/{total} vendors] - {label}")
                    if entity.get('detection_engines'):
                        vendors = ', '.join([d.get('engine', '') for d in entity['detection_engines'][:3]])
                        context_parts.append(f"  Detected by: {vendors}")

            ip_threats = [e for e in flagged if e.get('entity_type') == 'ip' and e.get('malicious_count', 0) > 0]
            domain_threats = [e for e in flagged if e.get('entity_type') == 'domain' and e.get('malicious_count', 0) > 0]

            if ip_threats or domain_threats:
                context_parts.append("\nMalicious Network Entities:")
                for entity in (ip_threats + domain_threats)[:5]:
                    mal = entity.get('malicious_count', 0)
                    sus = entity.get('suspicious_count', 0)
                    context_parts.append(f"  {entity.get('entity_type', '').upper()}: {entity.get('entity_value', 'N/A')} [{mal} malicious, {sus} suspicious]")

        suspicious_http = []
        if summary_data.get('http_sessions'):
            for session in summary_data['http_sessions'][:20]:
                uri = session.get('uri', '')
                host = session.get('host', '')
                if any(ext in uri.lower() for ext in ['.exe', '.dll', '.bat', '.ps1', '.sh']) or session.get('dst_port') not in ['80', '443']:
                    suspicious_http.append(session)

        if suspicious_http:
            context_parts.append("\n=== SUSPICIOUS HTTP ACTIVITY ===")
            for session in suspicious_http[:5]:
                context_parts.append(f"{session.get('method', 'GET')} {session.get('host', 'N/A')}{session.get('uri', '')} [{session.get('timestamp', 'N/A')}]")

        suspicious_dns = []
        if summary_data.get('dns_queries'):
            for query in summary_data['dns_queries'][:30]:
                qname = query.get('query_name', '').lower()
                if any(tld in qname for tld in ['.tk', '.ml', '.ga', '.cf', '.info', '.xyz']) or qname.replace('.', '').isdigit():
                    suspicious_dns.append(query)

        if suspicious_dns:
            context_parts.append("\n=== SUSPICIOUS DNS QUERIES ===")
            for query in suspicious_dns[:8]:
                context_parts.append(f"{query.get('query_name', 'N/A')} [{query.get('timestamp', 'N/A')}]")

        if summary_data.get('file_transfers'):
            context_parts.append("\n=== FILE TRANSFERS ===")
            for transfer in summary_data['file_transfers'][:5]:
                direction = transfer.get('direction', 'unknown').upper()
                url = transfer.get('url', transfer.get('host', 'N/A'))
                size = transfer.get('file_size', 'unknown')
                ctype = transfer.get('content_type', 'unknown')
                time = transfer.get('timestamp', 'N/A')
                context_parts.append(f"[{time}] {direction} from {url} | {size} bytes | {ctype}")

        top_flows = list(summary_data.get('top_flows', {}).items())[:8]
        if top_flows:
            context_parts.append("\n=== TOP NETWORK FLOWS ===")
            for flow, metadata in top_flows:
                if isinstance(metadata, dict):
                    packets = metadata.get('packet_count', 0)
                    bytes_total = metadata.get('total_bytes', 0)
                    context_parts.append(f"{flow}: {packets} pkts, {bytes_total} bytes")
                else:
                    context_parts.append(f"{flow}: {metadata} packets")

        return "\n".join(context_parts)

    def _format_rag_context(self, chunks: List[Dict[str, Any]]) -> str:
        context_parts = []

        context_parts.append("=== RETRIEVED RELEVANT DATA ===")
        context_parts.append(f"Retrieved {len(chunks)} relevant segments through similarity search.")
        context_parts.append("Each segment below is labeled with its type and contains specific metadata.\n")

        for i, chunk in enumerate(chunks, 1):
            metadata = chunk.get('metadata', {})
            packet_start = metadata.get('packet_range_start', -1)
            packet_end = metadata.get('packet_range_end', -1)
            chunk_type = metadata.get('chunk_type', 'unknown')

            if chunk_type == 'threat_intelligence' or packet_start == -1 or packet_end == -1:
                context_parts.append("=" * 70)
                context_parts.append("SEGMENT TYPE: VIRUSTOTAL THREAT INTELLIGENCE")
                context_parts.append("=" * 70)
                context_parts.append("SOURCE: Pre-analyzed security threat data from VirusTotal database")
                context_parts.append("CONTENT: Confirmed malicious/suspicious entities flagged by security vendors")

                threat_count = metadata.get('threat_count', 0)
                if threat_count > 0:
                    context_parts.append(f"THREATS IN SEGMENT: {threat_count} flagged entities")

                flagged_ips = metadata.get('ip_addresses', [])
                flagged_domains = metadata.get('domains', [])
                if flagged_ips:
                    context_parts.append(f"FLAGGED IPs: {', '.join(flagged_ips[:5])}")
                if flagged_domains:
                    context_parts.append(f"FLAGGED DOMAINS: {', '.join(flagged_domains[:5])}")

                context_parts.append("")
                context_parts.append(chunk['text'])
                context_parts.append("")

            else:
                context_parts.append("=" * 70)
                context_parts.append(f"SEGMENT TYPE: NETWORK TRAFFIC DATA")
                context_parts.append("=" * 70)
                context_parts.append(f"SOURCE: PCAP packet analysis")
                context_parts.append(f"PACKET RANGE: {packet_start} to {packet_end} ({packet_end - packet_start} packets)")

                timestamp_range = metadata.get('timestamp_range', {})
                if timestamp_range.get('start') and timestamp_range.get('end'):
                    context_parts.append(f"TIME RANGE: {timestamp_range['start']} to {timestamp_range['end']}")

                protocols = metadata.get('protocols', [])
                if protocols:
                    context_parts.append(f"PROTOCOLS: {', '.join(protocols)}")

                ips = metadata.get('ip_addresses', [])
                if ips:
                    context_parts.append(f"IPs INVOLVED: {', '.join(ips[:8])}")

                domains = metadata.get('domains', [])
                if domains:
                    context_parts.append(f"DOMAINS ACCESSED: {', '.join(domains[:8])}")

                has_threats = metadata.get('has_threats', False)
                threat_count = metadata.get('threat_count', 0)
                if has_threats and threat_count > 0:
                    context_parts.append(f"⚠️  CONTAINS {threat_count} THREAT(S) - See VirusTotal data for details")

                context_parts.append("")
                context_parts.append(chunk['text'])
                context_parts.append("")

        return "\n".join(context_parts)

    def get_chat_history(self, analysis_id: str) -> List[Dict[str, Any]]:
        return self.supabase.get_chat_history(analysis_id)

    def _handle_greeting_query(self, query: str) -> str:
        greetings_map = {
            'hi': 'Hello! I\'m ready to help you analyze this PCAP file. What would you like to know?',
            'hello': 'Hello! I\'m here to assist with your network traffic analysis. How can I help?',
            'hey': 'Hey! Ready to dive into the network analysis. What\'s your question?',
            'good morning': 'Good morning! Let\'s explore the network traffic together. What would you like to investigate?',
            'good afternoon': 'Good afternoon! I\'m here to help with your PCAP analysis. What can I answer for you?',
            'good evening': 'Good evening! Ready to analyze the network traffic. What would you like to know?'
        }

        query_lower = query.lower().strip()
        for greeting, response in greetings_map.items():
            if greeting in query_lower:
                return response

        return 'Hello! I\'m your network security analyst assistant. Ask me anything about the PCAP file analysis.'

    def _handle_help_query(self) -> str:
        return """I can help you analyze network traffic from this PCAP file. Here's what you can ask me about:

**Network Activity:**
- Which IPs communicated and what data was transferred?
- What protocols were used (TCP, UDP, HTTP, DNS, TLS)?
- What files were downloaded or uploaded?
- What domains or websites were accessed?

**Security Analysis:**
- Are there any malicious IPs or domains (based on VirusTotal)?
- What threats or suspicious activities were detected?
- Which file hashes were flagged as malicious?
- What security recommendations do you have?

**Specific Investigations:**
- What did IP address X.X.X.X do?
- What happened at a specific time?
- Which connections involved a specific domain?
- What's the timeline of events?

Just ask your question naturally, and I'll search through the network traffic and threat intelligence data to provide you with specific answers."""

    def _expand_query(self, query: str, classification: Dict[str, Any]) -> str:
        import re
        query_lower = query.lower()

        expansions = []

        # Extract IP address if present in query for targeted expansion
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', query)
        extracted_ip = ip_match.group(0) if ip_match else None

        # Enhanced forensic keyword expansions with protocol hints
        if 'mac address' in query_lower or 'hardware address' in query_lower or 'physical address' in query_lower:
            expansions.append('MAC address hardware address physical address Ethernet address layer2 address ARP ether NIC address')
            expansions.append('ARP table layer 2 Ethernet')  # Protocol hint
            if extracted_ip:
                expansions.append(f'ARP {extracted_ip} MAC of {extracted_ip}')

        if 'hostname' in query_lower or 'computer name' in query_lower or 'machine name' in query_lower or 'host name' in query_lower:
            expansions.append('hostname computer name machine name workstation name NetBIOS name DHCP hostname device name FQDN')
            expansions.append('DHCP Option 12 NetBIOS NBNS SMB')  # Protocol hints
            if extracted_ip:
                expansions.append(f'hostname of {extracted_ip} DHCP NetBIOS for {extracted_ip}')

        if 'user account' in query_lower or 'username' in query_lower or 'user' in query_lower or 'logged in' in query_lower:
            expansions.append('user account username user principal UPN account name authenticated user logged in user active user')
            expansions.append('Kerberos SMB authentication')  # Protocol hints
            if extracted_ip:
                expansions.append(f'user on {extracted_ip} Kerberos SMB user for {extracted_ip}')

        if ('domain' in query_lower and 'subdomain' not in query_lower) or 'workgroup' in query_lower or 'realm' in query_lower:
            expansions.append('domain realm Kerberos realm Active Directory AD domain Windows domain workgroup LDAP')
            expansions.append('DHCP Option 15 Kerberos SMB domain')  # Protocol hints

        if 'os' in query_lower or 'operating system' in query_lower or 'windows' in query_lower or 'system' in query_lower:
            expansions.append('operating system OS Windows version build number native OS SMB platform system information')
            expansions.append('SMB native_os DHCP vendor class')  # Protocol hints

        if 'infected' in query_lower or 'compromised' in query_lower or 'victim' in query_lower or 'malware' in query_lower:
            expansions.append('infected compromised victim malicious activity threat detected attack target patient zero malware')
            expansions.append('infected host compromised system Windows client')

        if 'infection' in query_lower and ('start' in query_lower or 'time' in query_lower or 'when' in query_lower):
            expansions.append('infection start infection time attack start initial compromise first malicious activity timeline first seen')

        # Detect queries about specific IP attributes
        if extracted_ip and any(term in query_lower for term in ['what is', 'find', 'tell me', 'show me']):
            # User asking about a specific IP's attributes
            if 'hostname' in query_lower or 'name' in query_lower:
                expansions.append(f'hostname computer name for IP {extracted_ip}')
            if 'mac' in query_lower:
                expansions.append(f'MAC hardware address for IP {extracted_ip}')
            if 'user' in query_lower:
                expansions.append(f'user account username for IP {extracted_ip}')

        # Existing expansions
        if 'file_analysis' in classification.get('topics', []):
            expansions.append('file transfer download upload HTTP')

        if 'domain_analysis' in classification.get('topics', []):
            expansions.append('DNS domain hostname')

        if 'ip_analysis' in classification.get('topics', []):
            expansions.append('IP address connection')

        if classification.get('is_threat_focused'):
            expansions.append('malicious threat VirusTotal security')

        if 'hash' in query_lower:
            expansions.append('SHA256 MD5 file hash checksum')

        # Detect common forensic questions and add targeted expansions
        if any(phrase in query_lower for phrase in ['infected client', 'compromised host', 'infected host', 'windows client', 'victim computer']):
            expansions.append('infected client compromised host victim Windows client infected system forensic investigation')

        if expansions:
            expanded = f"{query} {' '.join(expansions)}"
            print(f"[Query Expansion] Original: {query}")
            print(f"[Query Expansion] Added keywords: {expansions[:3]}")  # Show first 3 for brevity
            if extracted_ip:
                print(f"[Query Expansion] Detected IP: {extracted_ip}")
            return expanded

        return query

    def _filter_chunks_by_relevance(self, chunks: List[Dict[str, Any]], threshold: float = 0.6, query: str = "") -> List[Dict[str, Any]]:
        """Filter chunks by similarity threshold. Uses lower threshold for forensic queries."""
        if not chunks:
            return []

        # Use even lower threshold for forensic queries
        if self._is_forensic_query(query):
            threshold = 0.55
            print(f"[Threshold] Using forensic query threshold: {threshold}")
        else:
            print(f"[Threshold] Using standard threshold: {threshold}")

        filtered = []
        for chunk in chunks:
            # Check if this is a hybrid search result (has combined_score)
            if 'combined_score' in chunk:
                # Use combined score for hybrid results
                score = chunk['combined_score']
                score_type = "combined"
                # Log individual scores for debugging
                vector_score = chunk.get('vector_score', 0)
                bm25_score = chunk.get('bm25_score', 0)
                print(f"[Filter] Hybrid scores - vector: {vector_score:.3f}, bm25: {bm25_score:.3f}, combined: {score:.3f}")
            else:
                # Use similarity for pure vector results
                distance = chunk.get('distance', 1.0)
                score = 1 - distance
                score_type = "similarity"

            if score >= threshold:
                filtered.append(chunk)
                print(f"[Filter] ✓ Accepted chunk with {score_type} {score:.3f} (above threshold {threshold})")
            else:
                print(f"[Filter] ✗ Rejected chunk with {score_type} {score:.3f} (below threshold {threshold})")

        print(f"[Filter] Filtered {len(chunks)} chunks -> {len(filtered)} relevant chunks")
        return filtered

    def _is_forensic_query(self, query: str) -> bool:
        """Detect if query is asking for forensic host identification data."""
        query_lower = query.lower()
        forensic_keywords = [
            'hostname', 'host name', 'computer name', 'machine name',
            'mac address', 'hardware address', 'physical address',
            'ip address', 'ip of', 'ip for',
            'user account', 'username', 'user name', 'logged in user',
            'domain name', 'windows domain', 'ad domain',
            'infected client', 'compromised host', 'infected host',
            'victim computer', 'victim machine', 'victim host',
            'what is the', 'find the', 'tell me the'
        ]
        return any(keyword in query_lower for keyword in forensic_keywords)

    def _direct_json_forensic_fallback(self, analysis_id: str, query: str) -> Optional[Dict[str, Any]]:
        """
        Direct JSON fallback for forensic queries when RAG fails.
        Extracts answer directly from the JSON file without RAG.
        """
        try:
            import json
            import re

            # Load the full JSON file
            json_file = self.json_outputs_dir / f"{analysis_id}_full.json"
            if not json_file.exists():
                print(f"[JSON Fallback] JSON file not found: {json_file}")
                return None

            with open(json_file, 'r') as f:
                full_data = json.load(f)

            forensic_analysis = full_data.get('forensic_analysis', {})
            infected_hosts = forensic_analysis.get('infected_hosts', [])

            if not infected_hosts:
                print("[JSON Fallback] No infected hosts found in JSON")
                return None

            # Get the first (primary) infected host
            infected_host = infected_hosts[0]
            query_lower = query.lower()

            # Pattern matching to extract requested attribute
            answer = None
            attribute = None

            if any(keyword in query_lower for keyword in ['ip address', 'ip of']):
                answer = infected_host.get('ip', 'Unknown')
                attribute = 'IP address'
            elif any(keyword in query_lower for keyword in ['hostname', 'host name', 'computer name', 'machine name']):
                answer = infected_host.get('hostname', 'Unknown')
                attribute = 'hostname'
                # Mention data source
                data_source = infected_host.get('data_sources', {}).get('hostname', 'network protocol analysis')
            elif any(keyword in query_lower for keyword in ['mac address', 'hardware address', 'physical address']):
                answer = infected_host.get('mac', 'Unknown')
                attribute = 'MAC address'
                data_source = infected_host.get('data_sources', {}).get('mac', 'ARP table')
            elif any(keyword in query_lower for keyword in ['user account', 'username', 'user name', 'logged in']):
                answer = infected_host.get('user_account', 'Unknown')
                attribute = 'user account'
                data_source = infected_host.get('data_sources', {}).get('user_account', 'authentication records')
            elif any(keyword in query_lower for keyword in ['domain', 'windows domain']):
                answer = infected_host.get('domain', 'Unknown')
                attribute = 'domain'
                data_source = infected_host.get('data_sources', {}).get('domain', 'DHCP or Kerberos')
            elif any(keyword in query_lower for keyword in ['os', 'operating system']):
                answer = infected_host.get('os_info', 'Unknown')
                attribute = 'operating system'
                data_source = infected_host.get('data_sources', {}).get('os_info', 'SMB protocol')

            if answer and answer != 'Unknown':
                print(f"[JSON Fallback] ✓ Found {attribute}: {answer}")

                # Build a natural response
                if attribute == 'IP address':
                    response_text = f"The infected client IP address is **{answer}**."
                elif attribute == 'hostname':
                    response_text = f"The infected client hostname is **{answer}**. This information was obtained from {data_source}."
                elif attribute == 'MAC address':
                    response_text = f"The infected client MAC address (hardware address) is **{answer}**. This was identified from the {data_source}."
                elif attribute == 'user account':
                    response_text = f"The user account logged into the infected host is **{answer}**. This was identified through {data_source}."
                elif attribute == 'domain':
                    response_text = f"The Windows domain is **{answer}**. This was identified from {data_source}."
                elif attribute == 'operating system':
                    response_text = f"The operating system is **{answer}**. This information was obtained from the {data_source}."
                else:
                    response_text = f"The {attribute} is **{answer}**."

                # Add infection context
                response_text += f"\n\nThis system (IP {infected_host.get('ip', 'unknown')}) has been identified as infected with "
                response_text += f"{infected_host.get('infection_confidence', 'medium')} confidence based on "
                response_text += f"{infected_host.get('malicious_connections_count', 0)} malicious connections detected."

                return {
                    'status': 'success',
                    'response': response_text,
                    'method': 'direct_json_fallback'
                }

            print(f"[JSON Fallback] Could not determine what attribute user is asking about")
            return None

        except Exception as e:
            print(f"[JSON Fallback] Error: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    def _handle_fallback_to_summary(self, analysis_id: str, query: str) -> Dict[str, Any]:
        try:
            summary_file = self.json_outputs_dir / f"{analysis_id}_summary_enriched.json"
            if not summary_file.exists():
                return {
                    'status': 'error',
                    'message': 'I couldn\'t find relevant information to answer your specific question. The query might be too specific or use terms not present in the traffic data. Try asking about general statistics, threats, or rephrasing your question.'
                }

            with open(summary_file, 'r') as f:
                summary_data = json.load(f)

            context = self._format_summary_context(summary_data)

            chat_history = self.supabase.get_chat_history(analysis_id)
            formatted_history = [
                {'user': msg['user_query'], 'assistant': msg['llm_response']}
                for msg in chat_history[-3:]
            ]

            prompt = self.ollama.format_prompt_for_network_analysis(
                query=query,
                context=context,
                chat_history=formatted_history,
                analysis_mode='option2_fallback'
            )

            system_prompt = self.ollama.get_option2_system_prompt()
            response = self.ollama.generate_llm_response(
                prompt=prompt,
                stream=False,
                system_prompt=system_prompt
            )

            self.supabase.insert_chat_message(
                analysis_id=analysis_id,
                user_query=query,
                llm_response=response,
                retrieved_chunks=None
            )

            return {
                'status': 'success',
                'response': response,
                'mode': 'option2',
                'retrieved_chunks': None
            }

        except Exception as e:
            print(f"Error in fallback handler: {str(e)}")
            return {
                'status': 'error',
                'message': 'I couldn\'t find specific information to answer your question. Try asking about overall threats, statistics, or rephrasing your query.'
            }

    def _resolve_entity_references(self, query: str, session_memory: Dict[str, Any]) -> str:
        """Resolve entity references like 'this IP', 'the client' to actual values."""
        import re

        if not session_memory.get('exchanges'):
            return query

        last_exchange = session_memory['exchanges'][-1]
        last_entities = last_exchange.get('entities', {})

        resolved = query

        # Resolve IP references
        if any(ref in query.lower() for ref in ['this ip', 'that ip', 'the ip']):
            if last_entities.get('ips'):
                ip = last_entities['ips'][-1]
                resolved = re.sub(r'\bthis ip\b', ip, resolved, flags=re.IGNORECASE)
                resolved = re.sub(r'\bthat ip\b', ip, resolved, flags=re.IGNORECASE)
                resolved = re.sub(r'\bthe ip\b', ip, resolved, flags=re.IGNORECASE)

        # Resolve client/host references when we know which IP is the infected one
        if any(ref in query.lower() for ref in ['this client', 'that client', 'the client', 'this host', 'that host', 'the host', 'infected client', 'compromised host', 'the infected', 'the compromised']):
            if last_entities.get('ips'):
                ip = last_entities['ips'][-1]
                # Inject the IP into the query for better RAG matching
                resolved = re.sub(r'\bthis client\b', f'IP {ip}', resolved, flags=re.IGNORECASE)
                resolved = re.sub(r'\bthat client\b', f'IP {ip}', resolved, flags=re.IGNORECASE)
                resolved = re.sub(r'\bthe client\b', f'IP {ip}', resolved, flags=re.IGNORECASE)
                resolved = re.sub(r'\bthis host\b', f'IP {ip}', resolved, flags=re.IGNORECASE)
                resolved = re.sub(r'\bthat host\b', f'IP {ip}', resolved, flags=re.IGNORECASE)
                resolved = re.sub(r'\bthe host\b', f'IP {ip}', resolved, flags=re.IGNORECASE)
                resolved = re.sub(r'\binfected client\b', f'infected client IP {ip}', resolved, flags=re.IGNORECASE)
                resolved = re.sub(r'\bcompromised host\b', f'compromised host IP {ip}', resolved, flags=re.IGNORECASE)

        # Resolve domain references
        if any(ref in query.lower() for ref in ['this domain', 'that domain', 'the domain']):
            if last_entities.get('domains'):
                domain = last_entities['domains'][-1]
                resolved = re.sub(r'\bthis domain\b', domain, resolved, flags=re.IGNORECASE)
                resolved = re.sub(r'\bthat domain\b', domain, resolved, flags=re.IGNORECASE)
                resolved = re.sub(r'\bthe domain\b', domain, resolved, flags=re.IGNORECASE)

        return resolved

    def _extract_entities_from_history(self, chat_history: List[Dict[str, str]]) -> Dict[str, List[str]]:
        """Extract entities (IPs, domains) from chat history for Option 2."""
        import re

        entities = {'ips': [], 'domains': []}

        for exchange in chat_history[-3:]:  # Look at last 3 exchanges
            user_msg = exchange.get('user', '')
            assistant_msg = exchange.get('assistant', '')

            # Extract IPs from both user and assistant messages
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', user_msg + ' ' + assistant_msg)
            for ip in ips:
                if ip not in entities['ips']:
                    entities['ips'].append(ip)

            # Extract domains (basic pattern)
            domains = re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', user_msg + ' ' + assistant_msg)
            for domain in domains:
                if domain not in entities['domains'] and not re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
                    entities['domains'].append(domain)

        return entities

    def _resolve_entity_references_from_history(self, query: str, chat_history: List[Dict[str, str]], entities: Dict[str, List[str]]) -> str:
        """Resolve entity references for Option 2 using chat history."""
        import re

        resolved = query

        # Resolve IP references
        if any(ref in query.lower() for ref in ['this ip', 'that ip', 'the ip']):
            if entities.get('ips'):
                ip = entities['ips'][-1]
                resolved = re.sub(r'\bthis ip\b', ip, resolved, flags=re.IGNORECASE)
                resolved = re.sub(r'\bthat ip\b', ip, resolved, flags=re.IGNORECASE)
                resolved = re.sub(r'\bthe ip\b', ip, resolved, flags=re.IGNORECASE)

        # Resolve client/host references
        if any(ref in query.lower() for ref in ['this client', 'that client', 'the client', 'this host', 'that host', 'the host', 'infected client', 'compromised host']):
            if entities.get('ips'):
                ip = entities['ips'][-1]
                resolved = re.sub(r'\bthis client\b', f'IP {ip}', resolved, flags=re.IGNORECASE)
                resolved = re.sub(r'\bthat client\b', f'IP {ip}', resolved, flags=re.IGNORECASE)
                resolved = re.sub(r'\bthe client\b', f'IP {ip}', resolved, flags=re.IGNORECASE)
                resolved = re.sub(r'\bthis host\b', f'IP {ip}', resolved, flags=re.IGNORECASE)
                resolved = re.sub(r'\bthat host\b', f'IP {ip}', resolved, flags=re.IGNORECASE)
                resolved = re.sub(r'\bthe host\b', f'IP {ip}', resolved, flags=re.IGNORECASE)
                resolved = re.sub(r'\binfected client\b', f'infected client IP {ip}', resolved, flags=re.IGNORECASE)
                resolved = re.sub(r'\bcompromised host\b', f'compromised host IP {ip}', resolved, flags=re.IGNORECASE)

        # Resolve domain references
        if any(ref in query.lower() for ref in ['this domain', 'that domain', 'the domain']):
            if entities.get('domains'):
                domain = entities['domains'][-1]
                resolved = re.sub(r'\bthis domain\b', domain, resolved, flags=re.IGNORECASE)
                resolved = re.sub(r'\bthat domain\b', domain, resolved, flags=re.IGNORECASE)
                resolved = re.sub(r'\bthe domain\b', domain, resolved, flags=re.IGNORECASE)

        return resolved

    def _is_short_followup(self, query: str) -> bool:
        query_lower = query.lower().strip()
        short_followups = [
            'yes', 'yeah', 'yep', 'yup', 'sure', 'ok', 'okay',
            'no', 'nope', 'nah',
            'continue', 'more', 'tell me more', 'go on', 'keep going',
            'explain', 'elaborate', 'details', 'how', 'why',
            'what about', 'and', 'also'
        ]

        if len(query.split()) <= 3:
            for phrase in short_followups:
                if query_lower == phrase or query_lower.startswith(phrase + ' '):
                    return True

        return False

    def _enrich_query_with_session_memory(self, query: str, session_memory: Dict[str, Any]) -> str:
        """Enrich query with session memory context and resolve entity references."""
        import re

        if not session_memory['exchanges']:
            return query

        if not self._is_short_followup(query):
            # Even if not a short follow-up, still resolve entity references
            return self._resolve_entity_references(query, session_memory)

        last_exchange = session_memory['exchanges'][-1]
        last_user_query = last_exchange.get('user', '')
        last_mentioned_entities = last_exchange.get('entities', {})

        query_lower = query.lower().strip()

        # First, resolve entity references in the query
        resolved_query = self._resolve_entity_references(query, session_memory)

        if query_lower in ['yes', 'yeah', 'yep', 'yup', 'sure', 'ok', 'okay']:
            enriched = f"""[CONVERSATION CONTEXT: User previously asked: "{last_user_query}". User now says "{query}" - they want MORE DETAILS about that topic.]

Provide more detailed information about: {last_user_query}"""
            return enriched

        elif query_lower in ['continue', 'more', 'tell me more', 'go on', 'keep going', 'details', 'elaborate']:
            enriched = f"""[CONVERSATION CONTEXT: User previously asked: "{last_user_query}". User wants continuation.]

Continue with more details about: {last_user_query}"""
            return enriched

        elif any(ref in query_lower for ref in ['this ip', 'that ip', 'the ip', 'this client', 'that client', 'the client', 'this host', 'that host', 'the host', 'infected client', 'compromised host']):
            if last_mentioned_entities.get('ips'):
                ip = last_mentioned_entities['ips'][-1]
                # Return the resolved query which has the actual IP substituted
                print(f"[Session Memory] Resolved entity reference: '{query}' -> '{resolved_query}'")
                enriched = f"""[CONVERSATION CONTEXT: User is referring to IP {ip} from previous discussion about infected host.]

User's question about IP {ip}: {resolved_query}"""
                return enriched

        elif any(ref in query_lower for ref in ['this domain', 'that domain', 'the domain']):
            if last_mentioned_entities.get('domains'):
                domain = last_mentioned_entities['domains'][-1]
                enriched = f"""[CONVERSATION CONTEXT: User is referring to domain {domain} from previous discussion.]

User's question about domain {domain}: {resolved_query}"""
                return enriched

        # If resolved_query differs from original, use it
        if resolved_query != query:
            print(f"[Session Memory] Resolved entity reference: '{query}' -> '{resolved_query}'")
            return f"""[CONVERSATION CONTEXT: Previous question was: "{last_user_query}"]

Current follow-up: {resolved_query}"""

        return f"""[CONVERSATION CONTEXT: Previous question was: "{last_user_query}"]

Current follow-up: {query}"""

    def _format_session_memory_context(self, session_memory: Dict[str, Any]) -> str:
        """Format session memory for prompt context."""
        if not session_memory['exchanges']:
            return ""

        parts = ["=== SESSION MEMORY (Last 5 Exchanges) ==="]
        recent = session_memory['exchanges'][-5:]

        for i, exchange in enumerate(recent, 1):
            parts.append(f"\nExchange {i}:")
            parts.append(f"User: {exchange['user'][:100]}...")
            parts.append(f"You: {exchange['assistant'][:150]}...")

        if session_memory['entities_mentioned']['ips']:
            parts.append(f"\nIPs discussed: {', '.join(session_memory['entities_mentioned']['ips'][:10])}")

        if session_memory['entities_mentioned']['domains']:
            parts.append(f"Domains discussed: {', '.join(session_memory['entities_mentioned']['domains'][:10])}")

        if session_memory['vt_findings_shared']:
            parts.append(f"\nVirusTotal findings already shared for: {', '.join(list(session_memory['vt_findings_shared'])[:5])}")

        parts.append("===\n")
        return "\n".join(parts)

    def _update_session_memory(self, session_memory: Dict[str, Any], query: str, response: str, summary_data: Dict[str, Any]):
        """Update session memory with new exchange and extract entities."""
        import re

        exchange = {
            'user': query,
            'assistant': response,
            'entities': {'ips': [], 'domains': []}
        }

        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips_in_query = re.findall(ip_pattern, query)
        ips_in_response = re.findall(ip_pattern, response)

        all_ips = list(set(ips_in_query + ips_in_response))
        for ip in all_ips:
            if ip not in session_memory['entities_mentioned']['ips']:
                session_memory['entities_mentioned']['ips'].append(ip)
            exchange['entities']['ips'].append(ip)

        domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        domains_in_query = re.findall(domain_pattern, query.lower())
        domains_in_response = re.findall(domain_pattern, response.lower())

        all_domains = list(set(domains_in_query + domains_in_response))
        for domain in all_domains:
            if domain not in session_memory['entities_mentioned']['domains']:
                session_memory['entities_mentioned']['domains'].append(domain)
            exchange['entities']['domains'].append(domain)

        for ip in all_ips:
            if self._is_vt_finding_mentioned(ip, summary_data):
                session_memory['vt_findings_shared'].add(ip)

        for domain in all_domains:
            if self._is_vt_finding_mentioned(domain, summary_data):
                session_memory['vt_findings_shared'].add(domain)

        session_memory['exchanges'].append(exchange)

        if len(session_memory['exchanges']) > 10:
            session_memory['exchanges'].pop(0)

    def _is_vt_finding_mentioned(self, entity: str, summary_data: Dict[str, Any]) -> bool:
        """Check if an entity has VirusTotal findings in the summary."""
        vt_results = summary_data.get('virustotal_results', {})
        flagged = vt_results.get('flagged_entities', [])

        for item in flagged:
            if item.get('entity_value') == entity:
                return True
        return False

    def _extract_malware_timeline(self, summary_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract chronological timeline of suspicious events for malware analysis."""
        events = []

        vt_results = summary_data.get('virustotal_results', {})
        flagged_entities = {item['entity_value']: item for item in vt_results.get('flagged_entities', [])}

        tcp_conns = summary_data.get('tcp_connections', [])
        for conn in tcp_conns[:20]:
            dst_ip = conn.get('dst_ip', '')
            if dst_ip in flagged_entities:
                mal_count = flagged_entities[dst_ip].get('malicious_count', 0)
                if mal_count > 0:
                    events.append({
                        'time': conn.get('first_seen', 'N/A'),
                        'type': 'malicious_connection',
                        'description': f"Connection to malicious IP {dst_ip} (flagged by {mal_count} vendors)"
                    })

        for transfer in summary_data.get('file_transfers', [])[:15]:
            uri = transfer.get('uri', '').lower()
            host = transfer.get('host', '')
            if any(ext in uri for ext in ['.exe', '.dll', '.bat', '.ps1', '.sh', '.vbs']):
                desc = f"File download: {host}{uri[:50]}"
                if host in flagged_entities:
                    mal_count = flagged_entities[host].get('malicious_count', 0)
                    desc += f" (from malicious domain, {mal_count} vendors)"
                events.append({
                    'time': transfer.get('timestamp', 'N/A'),
                    'type': 'file_download',
                    'description': desc
                })

        for http in summary_data.get('http_sessions', [])[:20]:
            host = http.get('host', '')
            uri = http.get('uri', '')
            if host in flagged_entities and flagged_entities[host].get('malicious_count', 0) > 0:
                mal_count = flagged_entities[host].get('malicious_count', 0)
                events.append({
                    'time': http.get('timestamp', 'N/A'),
                    'type': 'malicious_http',
                    'description': f"HTTP {http.get('method', 'GET')} to malicious domain {host} (flagged by {mal_count} vendors)"
                })

        for dns in summary_data.get('dns_queries', [])[:20]:
            qname = dns.get('query_name', '').lower()
            if any(tld in qname for tld in ['.tk', '.ml', '.ga', '.cf']) or qname in flagged_entities:
                desc = f"DNS query for {qname}"
                if qname in flagged_entities:
                    mal_count = flagged_entities[qname].get('malicious_count', 0)
                    if mal_count > 0:
                        desc += f" (malicious, {mal_count} vendors)"
                events.append({
                    'time': dns.get('timestamp', 'N/A'),
                    'type': 'suspicious_dns',
                    'description': desc
                })

        events.sort(key=lambda x: x['time'])

        return events

    def _enrich_query_with_context(self, query: str, chat_history: List[Dict[str, str]]) -> str:
        """Enrich query with chat history context and resolve entity references (Option 2)."""
        import re

        if not chat_history or len(chat_history) == 0:
            return query

        # Extract entities from chat history
        entities = self._extract_entities_from_history(chat_history)

        if not self._is_short_followup(query):
            # Even if not a short follow-up, still resolve entity references
            return self._resolve_entity_references_from_history(query, chat_history, entities)

        last_exchange = chat_history[-1]
        last_user_query = last_exchange.get('user', '')
        last_assistant_response = last_exchange.get('assistant', '')

        query_lower = query.lower().strip()

        # First, resolve entity references in the query
        resolved_query = self._resolve_entity_references_from_history(query, chat_history, entities)

        if query_lower in ['yes', 'yeah', 'yep', 'yup', 'sure', 'ok', 'okay']:
            enriched = f"""[CONTEXT MEMORY: The user previously asked: "{last_user_query}"
I responded with information about this topic.
The user now says "{query}" - they want MORE DETAILS or ELABORATION on what I just discussed.]

User's current request: Provide more detailed information about {last_user_query}"""
            return enriched

        elif query_lower in ['no', 'nope', 'nah']:
            enriched = f"""[CONTEXT MEMORY: The user previously asked: "{last_user_query}"
I provided information about this.
The user now says "{query}" - they are indicating the information wasn't what they wanted or they disagree.]

User's current response: {query} (in response to the previous discussion)"""
            return enriched

        elif query_lower in ['continue', 'more', 'tell me more', 'go on', 'keep going', 'details', 'elaborate']:
            enriched = f"""[CONTEXT MEMORY: The user previously asked: "{last_user_query}"
I provided initial information.
The user now says "{query}" - they want additional details or continuation of that analysis.]

User's current request: Continue with more details about {last_user_query}"""
            return enriched

        elif any(ref in query_lower for ref in ['this ip', 'that ip', 'the ip', 'this client', 'that client', 'the client', 'this host', 'that host', 'the host']):
            if entities.get('ips'):
                ip = entities['ips'][-1]
                print(f"[Session Memory - Option 2] Resolved entity reference: '{query}' -> '{resolved_query}'")
                enriched = f"""[CONTEXT MEMORY: User is referring to IP {ip} from previous discussion.]

User's question about IP {ip}: {resolved_query}"""
                return enriched

        # If resolved_query differs from original, use it
        if resolved_query != query:
            print(f"[Session Memory - Option 2] Resolved entity reference: '{query}' -> '{resolved_query}'")
            return f"""[CONTEXT MEMORY: The user previously asked: "{last_user_query}"]

User's current follow-up question: {resolved_query}"""

        return f"""[CONTEXT MEMORY: The user previously asked: "{last_user_query}"]

User's current follow-up question: {query}"""
