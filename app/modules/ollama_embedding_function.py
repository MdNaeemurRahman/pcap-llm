from typing import List
from chromadb import Documents, EmbeddingFunction, Embeddings
import requests


class OllamaEmbeddingFunction(EmbeddingFunction):
    def __init__(self, base_url: str, model: str = "nomic-embed-text"):
        self.base_url = base_url.rstrip('/')
        self.model = model
        self._validate_connection()

    def _validate_connection(self) -> bool:
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if response.status_code != 200:
                raise ConnectionError(f"Ollama server not reachable at {self.base_url}")
            return True
        except Exception as e:
            raise ConnectionError(f"Failed to connect to Ollama: {str(e)}")

    def __call__(self, input: Documents) -> Embeddings:
        embeddings = []

        for text in input:
            embedding = self._generate_single_embedding(text)
            if embedding is None:
                raise ValueError(f"Failed to generate embedding for text: {text[:100]}...")
            embeddings.append(embedding)

        return embeddings

    def _generate_single_embedding(self, text: str) -> List[float]:
        url = f"{self.base_url}/api/embeddings"
        payload = {
            "model": self.model,
            "prompt": text
        }

        try:
            response = requests.post(url, json=payload, timeout=30)
            if response.status_code == 200:
                result = response.json()
                return result.get('embedding', None)
            else:
                print(f"Embedding generation failed: {response.status_code}")
                return None
        except Exception as e:
            print(f"Error generating embedding: {str(e)}")
            return None
