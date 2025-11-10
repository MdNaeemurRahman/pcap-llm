import os
from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore"
    )

    supabase_url: str = Field(alias="SUPABASE_URL")
    supabase_key: str = Field(alias="SUPABASE_KEY")

    ollama_base_url: str = Field(default="http://130.232.102.188:11434", alias="OLLAMA_BASE_URL")
    ollama_embedding_model: str = Field(default="nomic-embed-text", alias="OLLAMA_EMBEDDING_MODEL")
    ollama_llm_model: str = Field(default="llama3.2", alias="OLLAMA_LLM_MODEL")

    virustotal_api_key: str = Field(alias="VIRUSTOTAL_API_KEY")

    base_dir: Path = Path(__file__).parent.parent
    data_dir: Path = base_dir / "data"
    uploads_dir: Path = data_dir / "uploads"
    json_outputs_dir: Path = data_dir / "json_outputs"
    vector_db_dir: Path = data_dir / "vector_db"

settings = Settings()

os.makedirs(settings.uploads_dir, exist_ok=True)
os.makedirs(settings.json_outputs_dir, exist_ok=True)
os.makedirs(settings.vector_db_dir, exist_ok=True)
