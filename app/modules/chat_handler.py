import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from .ollama_client import OllamaClient
from .vector_store import VectorStoreManager
from .supabase_client import SupabaseManager
from .query_classifier import QueryClassifier
from .tshark_agent import TSharkAgent
from .compact_formatter import CompactFormatter

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
        self.compact_formatter = CompactFormatter()

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

            # Use compact formatter for enhanced summaries (50% token reduction)
            context = self.compact_formatter.format_enhanced_summary_for_llm(summary_data)

            chat_history = self.supabase.get_chat_history(analysis_id)
            formatted_history = [
                {'user': msg['user_query'], 'assistant': msg['llm_response']}
                for msg in chat_history[-5:]
            ]

            enriched_query = self._enrich_query_with_context(query, formatted_history)

            prompt = self.ollama.format_prompt_for_network_analysis(
                query=enriched_query,
                context=context,
                chat_history=formatted_history,
                analysis_mode='option1'
            )

            system_prompt = self.ollama.get_system_prompt()
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
            print(f"Performing similarity search with query: '{expanded_query}'")
            search_results = self.vector_store.similarity_search(
                collection_name=f"pcap_{analysis_id}",
                query_text=expanded_query,
                n_results=top_k
            )

            if search_results['count'] == 0:
                print("No relevant chunks found, falling back to summary-based response")
                return self._handle_fallback_to_summary(analysis_id, query)

            filtered_chunks = self._filter_chunks_by_relevance(search_results['chunks'], threshold=0.7)

            if len(filtered_chunks) == 0:
                print("All chunks filtered out due to low relevance, using fallback")
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
        context_parts = []

        context_parts.append("=== PCAP FILE SUMMARY ===")
        context_parts.append(f"File: {summary_data['file_info']['filename']}")
        context_parts.append(f"File Hash (SHA256): {summary_data['file_info']['file_hash']}")
        context_parts.append(f"Total Packets: {summary_data['statistics']['total_packets']}")
        context_parts.append(f"Unique IPs: {summary_data['statistics']['unique_ips_count']}")
        context_parts.append(f"Unique Domains: {summary_data['statistics']['unique_domains_count']}")

        context_parts.append("\n=== TOP PROTOCOLS ===")
        for proto, count in summary_data['statistics']['top_protocols'].items():
            context_parts.append(f"{proto}: {count} packets")

        if 'virustotal_results' in summary_data:
            vt_summary = summary_data['virustotal_results']['summary']
            context_parts.append("\n=== VIRUSTOTAL THREAT INTELLIGENCE ===")
            context_parts.append(f"Total Entities Queried: {vt_summary['total_queried']}")
            context_parts.append(f"Malicious Entities: {vt_summary['malicious_entities']}")
            context_parts.append(f"Suspicious Entities: {vt_summary['suspicious_entities']}")

            file_threats = []
            ip_threats = []
            domain_threats = []

            for entity in summary_data['virustotal_results']['flagged_entities']:
                if entity['entity_type'] == 'file':
                    file_threats.append(entity)
                elif entity['entity_type'] == 'ip':
                    ip_threats.append(entity)
                elif entity['entity_type'] == 'domain':
                    domain_threats.append(entity)

            if file_threats:
                context_parts.append("\n=== FILE HASH ANALYSIS ===")
                for entity in file_threats:
                    threat_info = f"File Hash: {entity.get('entity_value', 'Unknown')[:16]}... "
                    malicious_count = entity.get('malicious_count', 0)
                    harmless_count = entity.get('harmless_count', 0)
                    threat_info += f"(Malicious: {malicious_count}/{harmless_count + malicious_count} engines)"
                    if entity.get('threat_label'):
                        threat_info += f" - Threat: {entity['threat_label']}"
                    context_parts.append(threat_info)

                    if entity.get('detection_engines'):
                        context_parts.append("  Top Detections:")
                        for detection in entity['detection_engines'][:5]:
                            context_parts.append(f"    - {detection.get('engine', 'Unknown')}: {detection.get('result', 'Unknown')}")

            if ip_threats or domain_threats:
                context_parts.append("\n=== NETWORK THREATS ===")
                for entity in (ip_threats + domain_threats)[:10]:
                    entity_type = entity.get('entity_type', 'unknown').upper()
                    entity_value = entity.get('entity_value', 'Unknown')
                    malicious_count = entity.get('malicious_count', 0)
                    suspicious_count = entity.get('suspicious_count', 0)
                    context_parts.append(
                        f"{entity_type}: {entity_value} "
                        f"(Malicious: {malicious_count}, Suspicious: {suspicious_count})"
                    )

        if summary_data.get('http_sessions'):
            context_parts.append("\n=== HTTP SESSIONS (Sample) ===")
            for session in summary_data['http_sessions'][:5]:
                host = session.get('host', 'N/A')
                method = session.get('method', 'N/A')
                uri = session.get('uri', 'N/A')
                context_parts.append(f"{method} {host}{uri}")

        if summary_data.get('dns_queries'):
            context_parts.append("\n=== DNS QUERIES (Sample) ===")
            for query in summary_data['dns_queries'][:10]:
                query_name = query.get('query_name', 'N/A')
                context_parts.append(f"Query: {query_name}")

        context_parts.append("\n=== TOP NETWORK FLOWS (with Metadata) ===")
        for flow, metadata in list(summary_data.get('top_flows', {}).items())[:10]:
            if isinstance(metadata, dict):
                flow_info = f"{flow}: {metadata.get('packet_count', 0)} packets, {metadata.get('total_bytes', 0)} bytes"
                if metadata.get('first_seen') and metadata.get('last_seen'):
                    flow_info += f", Duration: {metadata['first_seen']} to {metadata['last_seen']}"
                context_parts.append(flow_info)
            else:
                context_parts.append(f"{flow}: {metadata} packets")

        if summary_data.get('tcp_connections'):
            context_parts.append("\n=== TCP CONNECTION STATES (Sample) ===")
            for conn in summary_data['tcp_connections'][:10]:
                conn_info = f"{conn.get('src_ip', 'N/A')}:{conn.get('src_port', 'N/A')} -> {conn.get('dst_ip', 'N/A')}:{conn.get('dst_port', 'N/A')}"
                conn_info += f" | State: {conn.get('state', 'UNKNOWN')}"
                if conn.get('established_timestamp'):
                    conn_info += f" | Established: {conn['established_timestamp']}"
                if conn.get('first_seen'):
                    conn_info += f" | First: {conn['first_seen']}"
                context_parts.append(conn_info)

        if summary_data.get('file_transfers'):
            context_parts.append("\n=== FILE TRANSFER INDICATORS ===")
            for transfer in summary_data['file_transfers'][:10]:
                transfer_info = f"[{transfer.get('timestamp', 'N/A')}] {transfer.get('direction', 'unknown').upper()}"
                if transfer.get('url'):
                    transfer_info += f" from {transfer['url']}"
                elif transfer.get('host'):
                    transfer_info += f" from {transfer['host']}"
                if transfer.get('file_size'):
                    transfer_info += f" | Size: {transfer['file_size']} bytes"
                if transfer.get('content_type'):
                    transfer_info += f" | Type: {transfer['content_type']}"
                context_parts.append(transfer_info)

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
        query_lower = query.lower()

        expansions = []

        if 'file_analysis' in classification['topics']:
            expansions.append('file transfer download upload HTTP')

        if 'domain_analysis' in classification['topics']:
            expansions.append('DNS domain hostname')

        if 'ip_analysis' in classification['topics']:
            expansions.append('IP address connection')

        if classification['is_threat_focused']:
            expansions.append('malicious threat VirusTotal security')

        if 'hash' in query_lower:
            expansions.append('SHA256 MD5 file hash checksum')

        if expansions:
            expanded = f"{query} {' '.join(expansions)}"
            print(f"Query expanded with context: {expansions}")
            return expanded

        return query

    def _filter_chunks_by_relevance(self, chunks: List[Dict[str, Any]], threshold: float = 0.7) -> List[Dict[str, Any]]:
        if not chunks:
            return []

        filtered = []
        for chunk in chunks:
            distance = chunk.get('distance', 1.0)
            similarity = 1 - distance

            if similarity >= threshold:
                filtered.append(chunk)
            else:
                print(f"Filtered out chunk with similarity {similarity:.3f} (below threshold {threshold})")

        print(f"Filtered {len(chunks)} chunks -> {len(filtered)} relevant chunks")
        return filtered

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

    def _enrich_query_with_context(self, query: str, chat_history: List[Dict[str, str]]) -> str:
        if not chat_history or len(chat_history) == 0:
            return query

        if not self._is_short_followup(query):
            return query

        last_exchange = chat_history[-1]
        last_user_query = last_exchange.get('user', '')
        last_assistant_response = last_exchange.get('assistant', '')

        query_lower = query.lower().strip()

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

        else:
            enriched = f"""[CONTEXT MEMORY: The user previously asked: "{last_user_query}"]

User's current follow-up question: {query}"""
            return enriched
