from typing import List
from chromadb import Documents, EmbeddingFunction, Embeddings


class HuggingFaceEmbeddingFunction(EmbeddingFunction):
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        try:
            from sentence_transformers import SentenceTransformer
            self.model_name = model_name
            full_model_name = f"sentence-transformers/{model_name}"
            print(f"[HuggingFace] Loading model: {full_model_name}")
            self.model = SentenceTransformer(full_model_name)
            print(f"[HuggingFace] Model {model_name} loaded successfully")
        except ImportError:
            raise ImportError(
                "sentence-transformers is required for HuggingFace embeddings. "
                "Install it with: pip install sentence-transformers"
            )
        except Exception as e:
            raise RuntimeError(f"Failed to load HuggingFace model {model_name}: {str(e)}")

    def __call__(self, input: Documents) -> Embeddings:
        try:
            embeddings = self.model.encode(
                input,
                show_progress_bar=False,
                convert_to_numpy=True,
                batch_size=32
            )
            return embeddings.tolist()
        except Exception as e:
            print(f"[HuggingFace] Error generating embeddings: {str(e)}")
            raise ValueError(f"Failed to generate embeddings: {str(e)}")

    def get_model_info(self) -> dict:
        return {
            "provider": "huggingface",
            "model_name": self.model_name,
            "max_seq_length": self.model.max_seq_length,
            "embedding_dimension": self.model.get_sentence_embedding_dimension()
        }
