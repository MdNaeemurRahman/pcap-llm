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

            prompt = self.ollama.format_prompt_for_network_analysis(
                query=query,
                context=context,
                chat_history=formatted_history,
                analysis_mode='option2'
            )

            system_prompt = self.ollama.get_system_prompt()
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
                    threat_info = f"File Hash: {entity['entity_value'][:16]}... "
                    threat_info += f"(Malicious: {entity['malicious_count']}/{entity.get('harmless_count', 0)+entity['malicious_count']} engines)"
                    if entity.get('threat_label'):
                        threat_info += f" - Threat: {entity['threat_label']}"
                    context_parts.append(threat_info)

                    if entity.get('detection_engines'):
                        context_parts.append("  Top Detections:")
                        for detection in entity['detection_engines'][:5]:
                            context_parts.append(f"    - {detection['engine']}: {detection['result']}")

            if ip_threats or domain_threats:
                context_parts.append("\n=== NETWORK THREATS ===")
                for entity in (ip_threats + domain_threats)[:10]:
                    context_parts.append(
                        f"{entity['entity_type'].upper()}: {entity['entity_value']} "
                        f"(Malicious: {entity['malicious_count']}, Suspicious: {entity['suspicious_count']})"
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

        context_parts.append("\n=== TOP NETWORK FLOWS ===")
        for flow, count in list(summary_data.get('top_flows', {}).items())[:10]:
            context_parts.append(f"{flow}: {count} packets")

        return "\n".join(context_parts)

    def _format_rag_context(self, chunks: List[Dict[str, Any]]) -> str:
        context_parts = []

        context_parts.append("=== RELEVANT NETWORK TRAFFIC DATA ===")
        context_parts.append(f"Retrieved {len(chunks)} relevant segments from the network capture:\n")

        for i, chunk in enumerate(chunks, 1):
            packet_start = chunk['metadata'].get('packet_range_start', -1)
            packet_end = chunk['metadata'].get('packet_range_end', -1)

            if packet_start == -1 or packet_end == -1:
                context_parts.append("--- VIRUSTOTAL THREAT INTELLIGENCE SEGMENT ---")
                context_parts.append("NOTE: This segment contains VirusTotal threat intelligence data.")
                context_parts.append("IPs, domains, and file hashes in this segment were analyzed by VirusTotal")
                context_parts.append("and flagged by multiple security vendors as malicious or suspicious.")
                context_parts.append("")
            else:
                context_parts.append(f"--- Network Traffic Segment: Packets {packet_start}-{packet_end} ---")

            context_parts.append(chunk['text'])
            context_parts.append("")

        return "\n".join(context_parts)

    def get_chat_history(self, analysis_id: str) -> List[Dict[str, Any]]:
        return self.supabase.get_chat_history(analysis_id)
