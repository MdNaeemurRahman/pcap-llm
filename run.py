#!/usr/bin/env python
import sys
import os

try:
    import uvicorn
    from app.config import settings

    print("=" * 60)
    print("PCAP LLM Analyzer - Starting Server")
    print("=" * 60)
    print(f"\nConfiguration:")
    print(f"  Supabase URL: {settings.supabase_url}")
    print(f"  Ollama URL: {settings.ollama_base_url}")
    print(f"  Ollama Embedding Model: {settings.ollama_embedding_model}")
    print(f"  Ollama LLM Model: {settings.ollama_llm_model}")
    print(f"  VirusTotal API: {'Configured' if settings.virustotal_api_key and settings.virustotal_api_key != 'your_virustotal_api_key_here' else 'NOT Configured'}")
    print(f"\n  Data Directory: {settings.data_dir}")
    print(f"  Uploads Directory: {settings.uploads_dir}")
    print(f"  JSON Outputs Directory: {settings.json_outputs_dir}")
    print(f"  Vector DB Directory: {settings.vector_db_dir}")
    print("\n" + "=" * 60)
    print("\nServer will start at: http://0.0.0.0:8000")
    print("Access the web interface at: http://localhost:8000")
    print("\nPress CTRL+C to stop the server")
    print("=" * 60 + "\n")

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)

except ImportError as e:
    print(f"\nError: Missing dependencies - {str(e)}")
    print("\nPlease install dependencies first:")
    print("  pip install -r requirements.txt")
    sys.exit(1)
except Exception as e:
    print(f"\nError starting server: {str(e)}")
    sys.exit(1)
