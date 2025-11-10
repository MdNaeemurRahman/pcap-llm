from supabase import create_client, Client
from typing import Dict, List, Any, Optional
from datetime import datetime


class SupabaseManager:
    def __init__(self, url: str, key: str):
        self.client: Client = create_client(url, key)

    def insert_analysis_record(
        self,
        filename: str,
        file_hash: str,
        analysis_mode: str
    ) -> Optional[str]:
        try:
            data = {
                'filename': filename,
                'file_hash': file_hash,
                'analysis_mode': analysis_mode,
                'status': 'uploaded'
            }

            result = self.client.table('pcap_analyses').insert(data).execute()

            if result.data and len(result.data) > 0:
                return result.data[0]['id']
            return None
        except Exception as e:
            print(f"Error inserting analysis record: {str(e)}")
            return None

    def update_analysis_status(
        self,
        analysis_id: str,
        status: str,
        stats: Optional[Dict[str, Any]] = None
    ) -> bool:
        try:
            update_data = {
                'status': status,
                'updated_at': datetime.utcnow().isoformat()
            }

            if stats:
                if 'total_packets' in stats:
                    update_data['total_packets'] = stats['total_packets']
                if 'top_protocols' in stats:
                    update_data['top_protocols'] = stats['top_protocols']
                if 'unique_ips_count' in stats:
                    update_data['unique_ips_count'] = stats['unique_ips_count']
                if 'unique_domains_count' in stats:
                    update_data['unique_domains_count'] = stats['unique_domains_count']

            result = self.client.table('pcap_analyses').update(update_data).eq('id', analysis_id).execute()

            return bool(result.data)
        except Exception as e:
            print(f"Error updating analysis status: {str(e)}")
            return False

    def bulk_insert_vt_results(
        self,
        analysis_id: str,
        vt_results: List[Dict[str, Any]]
    ) -> bool:
        try:
            if not vt_results:
                return True

            records = []
            for result in vt_results:
                record = {
                    'analysis_id': analysis_id,
                    'entity_type': result['entity_type'],
                    'entity_value': result['entity_value'],
                    'malicious_count': result['malicious_count'],
                    'last_analysis_stats': result['last_analysis_stats'],
                    'category': result.get('category'),
                    'queried_at': result['queried_at']
                }
                records.append(record)

            result = self.client.table('virustotal_results').insert(records).execute()

            return bool(result.data)
        except Exception as e:
            print(f"Error bulk inserting VT results: {str(e)}")
            return False

    def insert_chat_message(
        self,
        analysis_id: str,
        user_query: str,
        llm_response: str,
        retrieved_chunks: Optional[List[Dict[str, Any]]] = None
    ) -> bool:
        try:
            data = {
                'analysis_id': analysis_id,
                'user_query': user_query,
                'llm_response': llm_response,
                'retrieved_chunks': retrieved_chunks or []
            }

            result = self.client.table('chat_sessions').insert(data).execute()

            return bool(result.data)
        except Exception as e:
            print(f"Error inserting chat message: {str(e)}")
            return False

    def get_analysis_by_id(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        try:
            result = self.client.table('pcap_analyses').select('*').eq('id', analysis_id).execute()

            if result.data and len(result.data) > 0:
                return result.data[0]
            return None
        except Exception as e:
            print(f"Error getting analysis by ID: {str(e)}")
            return None

    def get_analysis_by_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        try:
            result = self.client.table('pcap_analyses').select('*').eq('file_hash', file_hash).execute()

            if result.data and len(result.data) > 0:
                return result.data[0]
            return None
        except Exception as e:
            print(f"Error getting analysis by hash: {str(e)}")
            return None

    def get_flagged_entities(self, analysis_id: str) -> List[Dict[str, Any]]:
        try:
            result = self.client.table('virustotal_results')\
                .select('*')\
                .eq('analysis_id', analysis_id)\
                .gt('malicious_count', 0)\
                .execute()

            return result.data if result.data else []
        except Exception as e:
            print(f"Error getting flagged entities: {str(e)}")
            return []

    def get_vt_results(self, analysis_id: str) -> List[Dict[str, Any]]:
        try:
            result = self.client.table('virustotal_results')\
                .select('*')\
                .eq('analysis_id', analysis_id)\
                .execute()

            return result.data if result.data else []
        except Exception as e:
            print(f"Error getting VT results: {str(e)}")
            return []

    def list_user_analyses(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        try:
            result = self.client.table('pcap_analyses')\
                .select('*')\
                .order('created_at', desc=True)\
                .limit(limit)\
                .offset(offset)\
                .execute()

            return result.data if result.data else []
        except Exception as e:
            print(f"Error listing analyses: {str(e)}")
            return []

    def get_chat_history(self, analysis_id: str) -> List[Dict[str, Any]]:
        try:
            result = self.client.table('chat_sessions')\
                .select('*')\
                .eq('analysis_id', analysis_id)\
                .order('timestamp', desc=False)\
                .execute()

            return result.data if result.data else []
        except Exception as e:
            print(f"Error getting chat history: {str(e)}")
            return []

    def bulk_insert_chunks_metadata(
        self,
        analysis_id: str,
        chunks: List[Dict[str, Any]]
    ) -> bool:
        try:
            if not chunks:
                return True

            records = []
            for chunk in chunks:
                record = {
                    'analysis_id': analysis_id,
                    'chunk_index': chunk['chunk_index'],
                    'chunk_text': chunk['chunk_text'],
                    'ip_addresses': chunk['metadata'].get('ip_addresses', []),
                    'domains': chunk['metadata'].get('domains', []),
                    'timestamp_range': chunk['metadata'].get('timestamp_range', {})
                }
                records.append(record)

            result = self.client.table('chunks_metadata').insert(records).execute()

            return bool(result.data)
        except Exception as e:
            print(f"Error bulk inserting chunks metadata: {str(e)}")
            return False

    def cleanup_old_analyses(self, days: int = 30) -> int:
        try:
            cutoff_date = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
            cutoff_date = cutoff_date.replace(day=cutoff_date.day - days)

            result = self.client.table('pcap_analyses')\
                .delete()\
                .lt('created_at', cutoff_date.isoformat())\
                .execute()

            return len(result.data) if result.data else 0
        except Exception as e:
            print(f"Error cleaning up old analyses: {str(e)}")
            return 0
