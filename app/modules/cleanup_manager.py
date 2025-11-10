from typing import Dict, Any, List
from datetime import datetime, timedelta
from .vector_store import VectorStoreManager
from .supabase_client import SupabaseManager
from pathlib import Path
import shutil


class CleanupManager:
    def __init__(
        self,
        vector_store: VectorStoreManager,
        supabase_manager: SupabaseManager,
        uploads_dir: str,
        json_outputs_dir: str
    ):
        self.vector_store = vector_store
        self.supabase = supabase_manager
        self.uploads_dir = Path(uploads_dir)
        self.json_outputs_dir = Path(json_outputs_dir)

    def cleanup_old_analyses(self, days: int = 30) -> Dict[str, Any]:
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            print(f"Cleaning up analyses older than {cutoff_date.isoformat()}")

            old_analyses = self._get_old_analyses(cutoff_date)

            results = {
                'total_found': len(old_analyses),
                'collections_deleted': 0,
                'files_deleted': 0,
                'supabase_records_deleted': 0,
                'errors': []
            }

            for analysis in old_analyses:
                analysis_id = analysis['id']

                try:
                    if self.vector_store.delete_collection(analysis_id):
                        results['collections_deleted'] += 1
                except Exception as e:
                    results['errors'].append(f"Failed to delete collection {analysis_id}: {str(e)}")

                try:
                    self._delete_analysis_files(analysis_id, analysis['filename'])
                    results['files_deleted'] += 1
                except Exception as e:
                    results['errors'].append(f"Failed to delete files for {analysis_id}: {str(e)}")

            deleted_count = self.supabase.cleanup_old_analyses(days)
            results['supabase_records_deleted'] = deleted_count

            print(f"Cleanup complete: {results}")
            return results

        except Exception as e:
            return {
                'error': str(e),
                'total_found': 0,
                'collections_deleted': 0,
                'files_deleted': 0,
                'supabase_records_deleted': 0
            }

    def _get_old_analyses(self, cutoff_date: datetime) -> List[Dict[str, Any]]:
        try:
            all_analyses = self.supabase.list_user_analyses(limit=1000)
            old_analyses = [
                a for a in all_analyses
                if datetime.fromisoformat(a['created_at'].replace('Z', '+00:00')) < cutoff_date
            ]
            return old_analyses
        except Exception as e:
            print(f"Error getting old analyses: {str(e)}")
            return []

    def _delete_analysis_files(self, analysis_id: str, filename: str):
        files_to_delete = [
            self.uploads_dir / filename,
            self.json_outputs_dir / f"{analysis_id}_summary.json",
            self.json_outputs_dir / f"{analysis_id}_summary_enriched.json",
            self.json_outputs_dir / f"{analysis_id}_full.json",
            self.json_outputs_dir / f"{analysis_id}_full_enriched.json"
        ]

        for file_path in files_to_delete:
            if file_path.exists():
                try:
                    file_path.unlink()
                    print(f"Deleted file: {file_path}")
                except Exception as e:
                    print(f"Failed to delete {file_path}: {str(e)}")

    def cleanup_failed_analyses(self) -> Dict[str, Any]:
        try:
            all_analyses = self.supabase.list_user_analyses(limit=1000)
            failed_analyses = [a for a in all_analyses if a['status'] == 'failed']

            results = {
                'total_failed': len(failed_analyses),
                'cleaned': 0,
                'errors': []
            }

            for analysis in failed_analyses:
                analysis_id = analysis['id']
                try:
                    self.vector_store.delete_collection(analysis_id)
                    self._delete_analysis_files(analysis_id, analysis['filename'])
                    results['cleaned'] += 1
                except Exception as e:
                    results['errors'].append(f"Failed to clean {analysis_id}: {str(e)}")

            return results

        except Exception as e:
            return {
                'error': str(e),
                'total_failed': 0,
                'cleaned': 0
            }

    def get_storage_stats(self) -> Dict[str, Any]:
        try:
            vector_health = self.vector_store.health_check()

            uploads_size = sum(
                f.stat().st_size for f in self.uploads_dir.rglob('*') if f.is_file()
            )
            json_size = sum(
                f.stat().st_size for f in self.json_outputs_dir.rglob('*') if f.is_file()
            )
            vector_db_size = sum(
                f.stat().st_size for f in Path(self.vector_store.persist_directory).rglob('*')
                if f.is_file()
            )

            return {
                'uploads_size_mb': round(uploads_size / (1024 * 1024), 2),
                'json_outputs_size_mb': round(json_size / (1024 * 1024), 2),
                'vector_db_size_mb': round(vector_db_size / (1024 * 1024), 2),
                'total_size_mb': round((uploads_size + json_size + vector_db_size) / (1024 * 1024), 2),
                'vector_collections': vector_health.get('collections_count', 0),
                'total_vectors': vector_health.get('total_vectors', 0)
            }

        except Exception as e:
            return {
                'error': str(e)
            }

    def delete_specific_analysis(self, analysis_id: str) -> bool:
        try:
            analysis = self.supabase.get_analysis_by_id(analysis_id)
            if not analysis:
                return False

            self.vector_store.delete_collection(analysis_id)
            self._delete_analysis_files(analysis_id, analysis['filename'])

            result = self.supabase.client.table('pcap_analyses').delete().eq('id', analysis_id).execute()

            return bool(result.data)

        except Exception as e:
            print(f"Error deleting analysis {analysis_id}: {str(e)}")
            return False

    def vacuum_vector_database(self) -> Dict[str, Any]:
        try:
            collections = self.vector_store.list_collections()
            orphaned_collections = []

            for col in collections:
                if col['name'].startswith('pcap_'):
                    pcap_id = col['name'].replace('pcap_', '')
                    analysis = self.supabase.get_analysis_by_id(pcap_id)

                    if not analysis:
                        orphaned_collections.append(col['name'])
                        self.vector_store.client.delete_collection(name=col['name'])

            return {
                'orphaned_collections': len(orphaned_collections),
                'collections_deleted': orphaned_collections
            }

        except Exception as e:
            return {
                'error': str(e)
            }
