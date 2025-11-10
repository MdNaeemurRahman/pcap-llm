import json
from pathlib import Path
from typing import Dict, Any, Optional
from .pcap_parser import PCAPParser
from .virustotal_client import VirusTotalClient
from .text_chunker import TextChunker
from .ollama_client import OllamaClient
from .vector_store import VectorStoreManager
from .supabase_client import SupabaseManager


class AnalysisPipeline:
    def __init__(
        self,
        supabase_manager: SupabaseManager,
        vt_client: VirusTotalClient,
        ollama_client: OllamaClient,
        vector_store: VectorStoreManager,
        uploads_dir: str,
        json_outputs_dir: str
    ):
        self.supabase = supabase_manager
        self.vt_client = vt_client
        self.ollama = ollama_client
        self.vector_store = vector_store
        self.uploads_dir = Path(uploads_dir)
        self.json_outputs_dir = Path(json_outputs_dir)

    def process_option1(self, file_path: str, filename: str, analysis_id: str) -> Dict[str, Any]:
        try:
            print(f"\n=== Starting Option 1 Analysis for {filename} ===")

            self.supabase.update_analysis_status(analysis_id, 'parsing')
            print("Parsing PCAP file...")

            parser = PCAPParser(file_path)
            summary_output = self.json_outputs_dir / f"{analysis_id}_summary.json"
            summary = parser.generate_summary_json(str(summary_output))

            stats = {
                'total_packets': summary['statistics']['total_packets'],
                'top_protocols': summary['statistics']['top_protocols'],
                'unique_ips_count': summary['statistics']['unique_ips_count'],
                'unique_domains_count': summary['statistics']['unique_domains_count']
            }
            self.supabase.update_analysis_status(analysis_id, 'enriching', stats)

            print("Identifying high-priority entities for VirusTotal queries...")
            prioritized = parser.get_prioritized_entities(max_ips=5, max_domains=5)

            ips = prioritized['ips']
            domains = prioritized['domains']

            print(f"Selected {len(ips)} IPs and {len(domains)} domains (out of {prioritized['total_ips_found']} IPs and {prioritized['total_domains_found']} domains)")

            file_hash = summary['file_info']['file_hash']
            file_hashes = [file_hash] if file_hash else []

            existing_vt_results = self.supabase.get_vt_results(analysis_id)
            print(f"Found {len(existing_vt_results)} existing VirusTotal results in cache")

            vt_results = self.vt_client.batch_query_entities(ips, domains, file_hashes, existing_vt_results)

            vt_output = self.json_outputs_dir / f"{analysis_id}_virustotal.json"
            with open(vt_output, 'w') as f:
                json.dump(vt_results, f, indent=2)
            print(f"Saved VirusTotal results to: {vt_output}")

            enriched_summary = self.vt_client.enrich_json_with_vt(summary, vt_results)

            enriched_output = self.json_outputs_dir / f"{analysis_id}_summary_enriched.json"
            with open(enriched_output, 'w') as f:
                json.dump(enriched_summary, f, indent=2)

            self.supabase.bulk_insert_vt_results(analysis_id, vt_results)

            self.supabase.update_analysis_status(analysis_id, 'ready', stats, current_mode='option1')

            print("=== Option 1 Analysis Complete ===\n")

            return {
                'status': 'success',
                'analysis_id': analysis_id,
                'summary': enriched_summary,
                'vt_results': vt_results
            }

        except Exception as e:
            print(f"Error in Option 1 pipeline: {str(e)}")
            self.supabase.update_analysis_status(analysis_id, 'failed')
            return {
                'status': 'error',
                'message': str(e)
            }

    def process_option2(self, file_path: str, filename: str, analysis_id: str) -> Dict[str, Any]:
        try:
            print(f"\n=== Starting Option 2 Analysis for {filename} ===")

            self.supabase.update_analysis_status(analysis_id, 'parsing')
            print("Parsing PCAP file (full mode)...")

            parser = PCAPParser(file_path)
            full_output = self.json_outputs_dir / f"{analysis_id}_full.json"
            full_data = parser.generate_full_json(str(full_output))

            stats = {
                'total_packets': full_data['statistics']['total_packets'],
                'top_protocols': full_data['statistics']['top_protocols'],
                'unique_ips_count': full_data['statistics']['unique_ips_count'],
                'unique_domains_count': full_data['statistics']['unique_domains_count']
            }
            self.supabase.update_analysis_status(analysis_id, 'enriching', stats)

            print("Identifying high-priority entities for VirusTotal queries...")
            prioritized = parser.get_prioritized_entities(max_ips=5, max_domains=5)

            ips = prioritized['ips']
            domains = prioritized['domains']

            print(f"Selected {len(ips)} IPs and {len(domains)} domains (out of {prioritized['total_ips_found']} IPs and {prioritized['total_domains_found']} domains)")

            file_hash = full_data['file_info']['file_hash']
            file_hashes = [file_hash] if file_hash else []

            existing_vt_results = self.supabase.get_vt_results(analysis_id)
            print(f"Found {len(existing_vt_results)} existing VirusTotal results in cache")

            vt_results = self.vt_client.batch_query_entities(ips, domains, file_hashes, existing_vt_results)

            vt_output = self.json_outputs_dir / f"{analysis_id}_virustotal.json"
            with open(vt_output, 'w') as f:
                json.dump(vt_results, f, indent=2)
            print(f"Saved VirusTotal results to: {vt_output}")

            enriched_full = self.vt_client.enrich_json_with_vt(full_data, vt_results)

            enriched_output = self.json_outputs_dir / f"{analysis_id}_full_enriched.json"
            with open(enriched_output, 'w') as f:
                json.dump(enriched_full, f, indent=2)

            self.supabase.bulk_insert_vt_results(analysis_id, vt_results)

            self.supabase.update_analysis_status(analysis_id, 'embedding')
            print("Chunking and embedding data with VirusTotal intelligence...")

            chunker = TextChunker(max_chunk_size=100)
            chunks = chunker.chunk_by_packet_range(enriched_full, vt_results)

            print(f"Created {len(chunks)} chunks (with integrated threat intelligence)")

            print("Storing in vector database...")
            collection = self.vector_store.create_collection_for_pcap(analysis_id, delete_existing=True)
            self.vector_store.add_chunks_to_collection(f"pcap_{analysis_id}", chunks)

            self.supabase.bulk_insert_chunks_metadata(analysis_id, chunks)

            self.supabase.update_analysis_status(analysis_id, 'ready', stats, current_mode='option2')

            print("=== Option 2 Analysis Complete ===\n")

            return {
                'status': 'success',
                'analysis_id': analysis_id,
                'full_data': enriched_full,
                'vt_results': vt_results,
                'chunks_count': len(chunks)
            }

        except Exception as e:
            print(f"Error in Option 2 pipeline: {str(e)}")
            self.supabase.update_analysis_status(analysis_id, 'failed')
            return {
                'status': 'error',
                'message': str(e)
            }

    def get_analysis_results(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        try:
            analysis = self.supabase.get_analysis_by_id(analysis_id)
            if not analysis:
                return None

            result = {
                'analysis': analysis,
                'vt_results': self.supabase.get_vt_results(analysis_id),
                'flagged_entities': self.supabase.get_flagged_entities(analysis_id),
                'chat_history': self.supabase.get_chat_history(analysis_id)
            }

            if analysis['analysis_mode'] == 'option1':
                summary_file = self.json_outputs_dir / f"{analysis_id}_summary_enriched.json"
                if summary_file.exists():
                    with open(summary_file, 'r') as f:
                        result['summary_data'] = json.load(f)

            elif analysis['analysis_mode'] == 'option2':
                full_file = self.json_outputs_dir / f"{analysis_id}_full_enriched.json"
                if full_file.exists():
                    with open(full_file, 'r') as f:
                        result['full_data'] = json.load(f)

            return result

        except Exception as e:
            print(f"Error getting analysis results: {str(e)}")
            return None

    def cleanup_temp_files(self, analysis_id: str):
        try:
            temp_files = [
                self.json_outputs_dir / f"{analysis_id}_summary.json",
                self.json_outputs_dir / f"{analysis_id}_full.json"
            ]

            for temp_file in temp_files:
                if temp_file.exists():
                    temp_file.unlink()

            print(f"Cleaned up temporary files for analysis {analysis_id}")
        except Exception as e:
            print(f"Error cleaning up temp files: {str(e)}")
