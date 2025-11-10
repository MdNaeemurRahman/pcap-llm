import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from .ollama_client import OllamaClient
from .vector_store import VectorStoreManager
from .supabase_client import SupabaseManager
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

            context = self._format_summary_context(summary_data)

            chat_history = self.supabase.get_chat_history(analysis_id)
            formatted_history = [
                {'user': msg['user_query'], 'assistant': msg['llm_response']}
                for msg in chat_history[-5:]
            ]

            prompt = self.ollama.format_prompt_for_network_analysis(
                query=query,
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

    def handle_option2_query(self, analysis_id: str, query: str, top_k: int = 5) -> Dict[str, Any]:
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

            print("Performing similarity search...")
            search_results = self.vector_store.similarity_search(
                collection_name=f"pcap_{analysis_id}",
                query_text=query,
                n_results=top_k
            )

            if search_results['count'] == 0:
                return {
                    'status': 'error',
                    'message': 'No relevant chunks found for your query. Try rephrasing or asking about general statistics.'
                }

            context = self._format_rag_context(search_results['chunks'])

            chat_history = self.supabase.get_chat_history(analysis_id)
            formatted_history = [
                {'user': msg['user_query'], 'assistant': msg['llm_response']}
                for msg in chat_history[-5:]
            ]

            prompt = self.ollama.format_prompt_for_option2_analysis(
                query=query,
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
                for chunk in search_results['chunks']
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
