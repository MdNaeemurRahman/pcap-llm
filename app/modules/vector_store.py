import chromadb
from chromadb.config import Settings
from chromadb import Collection
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime, timedelta
from .ollama_embedding_function import OllamaEmbeddingFunction


class VectorStoreManager:
    def __init__(
        self,
        persist_directory: str,
        ollama_base_url: str,
        embedding_model: str = "nomic-embed-text"
    ):
        self.persist_directory = Path(persist_directory)
        self.persist_directory.mkdir(parents=True, exist_ok=True)
        self.ollama_base_url = ollama_base_url
        self.embedding_model = embedding_model

        self.embedding_function = OllamaEmbeddingFunction(
            base_url=ollama_base_url,
            model=embedding_model
        )

        self.client = chromadb.PersistentClient(
            path=str(self.persist_directory),
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True
            )
        )

    def create_collection_for_pcap(
        self,
        pcap_id: str,
        delete_existing: bool = False
    ) -> Collection:
        collection_name = f"pcap_{pcap_id}"

        if delete_existing:
            try:
                self.client.delete_collection(name=collection_name)
                print(f"Deleted existing collection: {collection_name}")
            except Exception:
                pass

        try:
            collection = self.client.get_collection(
                name=collection_name,
                embedding_function=self.embedding_function
            )
            print(f"Retrieved existing collection: {collection_name}")
            return collection
        except Exception:
            collection = self.client.create_collection(
                name=collection_name,
                metadata={
                    "pcap_id": pcap_id,
                    "embedding_model": self.embedding_model,
                    "created_at": datetime.utcnow().isoformat(),
                    "hnsw:space": "cosine",
                    "hnsw:construction_ef": 200,
                    "hnsw:M": 16,
                    "hnsw:search_ef": 100
                },
                embedding_function=self.embedding_function
            )
            print(f"Created new collection: {collection_name}")
            return collection

    def add_chunks_to_collection(
        self,
        collection_name: str,
        chunks: List[Dict[str, Any]]
    ) -> bool:
        try:
            collection = self.client.get_collection(
                name=collection_name,
                embedding_function=self.embedding_function
            )

            documents = []
            metadatas = []
            ids = []

            for chunk in chunks:
                doc_id = f"chunk_{chunk['chunk_index']}"
                documents.append(chunk['chunk_text'])

                metadata = {
                    'chunk_index': chunk['chunk_index'],
                    'packet_range_start': chunk['packet_range']['start'],
                    'packet_range_end': chunk['packet_range']['end'],
                    'packet_count': chunk['metadata']['packet_count']
                }

                if chunk['metadata'].get('ip_addresses'):
                    metadata['ip_addresses'] = ','.join(chunk['metadata']['ip_addresses'][:10])
                if chunk['metadata'].get('domains'):
                    metadata['domains'] = ','.join(chunk['metadata']['domains'][:10])
                if chunk['metadata'].get('protocols'):
                    metadata['protocols'] = ','.join(chunk['metadata']['protocols'])

                metadatas.append(metadata)
                ids.append(doc_id)

            if documents:
                batch_size = 100
                total_batches = (len(documents) + batch_size - 1) // batch_size
                print(f"[Vector Store] Processing {len(documents)} chunks in {total_batches} batches")

                for i in range(0, len(documents), batch_size):
                    batch_docs = documents[i:i + batch_size]
                    batch_metas = metadatas[i:i + batch_size]
                    batch_ids = ids[i:i + batch_size]

                    batch_num = i//batch_size + 1
                    print(f"[Vector Store] Embedding and storing batch {batch_num}/{total_batches} ({len(batch_docs)} chunks)...")

                    collection.add(
                        documents=batch_docs,
                        metadatas=batch_metas,
                        ids=batch_ids
                    )
                    print(f"[Vector Store] Batch {batch_num}/{total_batches} complete")

                print(f"[Vector Store] Successfully stored {len(documents)} chunks in collection")
                return True
            else:
                print("No valid chunks to add")
                return False

        except Exception as e:
            print(f"Error adding chunks to collection: {str(e)}")
            return False

    def similarity_search(
        self,
        collection_name: str,
        query_text: str,
        n_results: int = 5,
        where: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        try:
            print(f"[Vector Store] Starting similarity search in collection: {collection_name}")
            collection = self.client.get_collection(
                name=collection_name,
                embedding_function=self.embedding_function
            )

            query_params = {
                "query_texts": [query_text],
                "n_results": n_results,
                "include": ['documents', 'metadatas', 'distances']
            }

            if where:
                query_params["where"] = where

            print(f"[Vector Store] Querying for top {n_results} similar chunks...")
            results = collection.query(**query_params)
            print(f"[Vector Store] Similarity search complete")

            formatted_results = {
                'chunks': [],
                'count': len(results['documents'][0]) if results['documents'] else 0
            }

            if results['documents'] and results['documents'][0]:
                for i in range(len(results['documents'][0])):
                    chunk_data = {
                        'text': results['documents'][0][i],
                        'metadata': results['metadatas'][0][i],
                        'distance': results['distances'][0][i] if results['distances'] else None
                    }
                    formatted_results['chunks'].append(chunk_data)

            return formatted_results

        except Exception as e:
            print(f"Error during similarity search: {str(e)}")
            return {'chunks': [], 'count': 0}

    def get_collection_by_pcap_id(self, pcap_id: str) -> Optional[Collection]:
        collection_name = f"pcap_{pcap_id}"
        try:
            return self.client.get_collection(
                name=collection_name,
                embedding_function=self.embedding_function
            )
        except Exception:
            return None

    def collection_exists(self, pcap_id: str) -> bool:
        collection_name = f"pcap_{pcap_id}"
        try:
            self.client.get_collection(name=collection_name)
            return True
        except Exception:
            return False

    def delete_collection(self, pcap_id: str) -> bool:
        collection_name = f"pcap_{pcap_id}"
        try:
            self.client.delete_collection(name=collection_name)
            print(f"Deleted collection: {collection_name}")
            return True
        except Exception as e:
            print(f"Error deleting collection: {str(e)}")
            return False

    def list_collections(self) -> List[Dict[str, Any]]:
        try:
            collections = self.client.list_collections()
            result = []
            for col in collections:
                info = {
                    'name': col.name,
                    'count': col.count(),
                    'metadata': col.metadata
                }
                result.append(info)
            return result
        except Exception as e:
            print(f"Error listing collections: {str(e)}")
            return []

    def get_collection_stats(self, pcap_id: str) -> Optional[Dict[str, Any]]:
        try:
            collection = self.get_collection_by_pcap_id(pcap_id)
            if collection:
                count = collection.count()
                return {
                    'name': collection.name,
                    'count': count,
                    'metadata': collection.metadata
                }
            return None
        except Exception as e:
            print(f"Error getting collection stats: {str(e)}")
            return None

    def cleanup_old_collections(self, days: int = 30) -> int:
        try:
            deleted_count = 0
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            collections = self.client.list_collections()

            for col in collections:
                if col.metadata and 'created_at' in col.metadata:
                    created_at = datetime.fromisoformat(col.metadata['created_at'])
                    if created_at < cutoff_date:
                        try:
                            self.client.delete_collection(name=col.name)
                            deleted_count += 1
                            print(f"Deleted old collection: {col.name}")
                        except Exception as e:
                            print(f"Error deleting collection {col.name}: {str(e)}")

            return deleted_count
        except Exception as e:
            print(f"Error during cleanup: {str(e)}")
            return 0

    def health_check(self) -> Dict[str, Any]:
        try:
            collections = self.client.list_collections()
            total_vectors = sum(col.count() for col in collections)

            return {
                'status': 'healthy',
                'collections_count': len(collections),
                'total_vectors': total_vectors,
                'persist_directory': str(self.persist_directory),
                'embedding_model': self.embedding_model
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e)
            }
