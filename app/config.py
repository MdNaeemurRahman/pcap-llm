import os
import sys
import re
from pathlib import Path
from pydantic import Field, field_validator
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

    @field_validator('supabase_url')
    @classmethod
    def validate_supabase_url(cls, v: str) -> str:
        if not v or v == "your_supabase_url_here":
            print("\n" + "="*60)
            print("ERROR: Supabase URL is not configured!")
            print("="*60)
            print("\nPlease update the .env file with your actual Supabase URL.")
            print("Your Supabase URL should look like:")
            print("  https://[project-ref].supabase.co")
            print("\nYou can get this from your Supabase project dashboard:")
            print("  1. Go to https://supabase.com/dashboard")
            print("  2. Select your project")
            print("  3. Go to Settings > API")
            print("  4. Copy the 'Project URL'")
            print("="*60 + "\n")
            sys.exit(1)

        url_pattern = r'^https://[a-z0-9]{20}\.supabase\.co$'
        if not re.match(url_pattern, v):
            print("\n" + "="*60)
            print("WARNING: Supabase URL format may be invalid!")
            print("="*60)
            print(f"\nProvided URL: {v}")
            print("\nExpected format: https://[20-character-ref].supabase.co")
            print("\nAttempting to continue, but this may cause connection errors.")
            print("If you experience issues, please verify your Supabase URL.")
            print("="*60 + "\n")

        return v

    @field_validator('supabase_key')
    @classmethod
    def validate_supabase_key(cls, v: str) -> str:
        if not v or v == "your_supabase_anon_key_here":
            print("\n" + "="*60)
            print("ERROR: Supabase API Key is not configured!")
            print("="*60)
            print("\nPlease update the .env file with your actual Supabase anon key.")
            print("You can get this from your Supabase project dashboard:")
            print("  1. Go to https://supabase.com/dashboard")
            print("  2. Select your project")
            print("  3. Go to Settings > API")
            print("  4. Copy the 'anon public' key")
            print("="*60 + "\n")
            sys.exit(1)

        return v

settings = Settings()

os.makedirs(settings.uploads_dir, exist_ok=True)
os.makedirs(settings.json_outputs_dir, exist_ok=True)
os.makedirs(settings.vector_db_dir, exist_ok=True)
