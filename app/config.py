import os
from pathlib import Path
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    supabase_url: str
    supabase_key: str

    ollama_base_url: str = "http://130.232.102.188:11434"
    ollama_embedding_model: str = "nomic-embed-text"
    ollama_llm_model: str = "llama3.2"

    virustotal_api_key: str

    base_dir: Path = Path(__file__).parent.parent
    data_dir: Path = base_dir / "data"
    uploads_dir: Path = data_dir / "uploads"
    json_outputs_dir: Path = data_dir / "json_outputs"
    vector_db_dir: Path = data_dir / "vector_db"

    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "ignore"

        fields = {
            'supabase_url': {'env': 'SUPABASE_URL'},
            'supabase_key': {'env': 'SUPABASE_KEY'},
            'ollama_base_url': {'env': 'OLLAMA_BASE_URL'},
            'ollama_embedding_model': {'env': 'OLLAMA_EMBEDDING_MODEL'},
            'ollama_llm_model': {'env': 'OLLAMA_LLM_MODEL'},
            'virustotal_api_key': {'env': 'VIRUSTOTAL_API_KEY'},
        }

settings = Settings()

os.makedirs(settings.uploads_dir, exist_ok=True)
os.makedirs(settings.json_outputs_dir, exist_ok=True)
os.makedirs(settings.vector_db_dir, exist_ok=True)
