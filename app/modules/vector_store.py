import chromadb
from chromadb.config import Settings
from typing import Dict, List, Any, Optional
from pathlib import Path


class VectorStoreManager:
    def __init__(self, persist_directory: str):
        self.persist_directory = Path(persist_directory)
        self.persist_directory.mkdir(parents=True, exist_ok=True)

        self.client = chromadb.PersistentClient(
            path=str(self.persist_directory)
        )

    def create_collection_for_pcap(self, pcap_id: str, delete_existing: bool = False) -> chromadb.Collection:
        collection_name = f"pcap_{pcap_id}"

        if delete_existing:
            try:
                self.client.delete_collection(name=collection_name)
            except Exception:
                pass

        try:
            collection = self.client.get_collection(name=collection_name)
            return collection
        except Exception:
            collection = self.client.create_collection(
                name=collection_name,
                metadata={"pcap_id": pcap_id}
            )
            return collection

    def add_chunks_to_collection(
        self,
        collection_name: str,
        chunks: List[Dict[str, Any]],
        embeddings: List[List[float]]
    ) -> bool:
        try:
            collection = self.client.get_collection(name=collection_name)

            documents = []
            metadatas = []
            ids = []

            for i, (chunk, embedding) in enumerate(zip(chunks, embeddings)):
                if embedding is None:
                    print(f"Warning: Skipping chunk {i} due to missing embedding")
                    continue

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
                collection.add(
                    documents=documents,
                    embeddings=embeddings[:len(documents)],
                    metadatas=metadatas,
                    ids=ids
                )
                print(f"Added {len(documents)} chunks to collection")
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
        query_embedding: List[float],
        n_results: int = 5
    ) -> Dict[str, Any]:
        try:
            collection = self.client.get_collection(name=collection_name)

            results = collection.query(
                query_embeddings=[query_embedding],
                n_results=n_results,
                include=['documents', 'metadatas', 'distances']
            )

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

    def get_collection_by_pcap_id(self, pcap_id: str) -> Optional[chromadb.Collection]:
        collection_name = f"pcap_{pcap_id}"
        try:
            return self.client.get_collection(name=collection_name)
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

    def list_collections(self) -> List[str]:
        try:
            collections = self.client.list_collections()
            return [col.name for col in collections]
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
