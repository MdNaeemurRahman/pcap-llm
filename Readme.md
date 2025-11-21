# PCAP LLM Analyzer

An AI-powered network traffic analysis tool that combines PCAP parsing, threat intelligence, and Large Language Models to provide intelligent insights into network captures.

## Features

- **PCAP File Processing**: Parse network traffic captures (.pcap, .pcapng, .cap files)
- **Three Analysis Modes**:
  - **Option 1 (Summary Chat)**: Fast analysis with summary data for quick threat assessment
  - **Option 2 (Full Context Chat)**: Deep analysis with RAG for comprehensive packet-level investigation
  - **Option 3 (Agentic TShark)**: NEW! AI-powered dynamic analysis where LLM decides and executes TShark commands on-demand
- **VirusTotal Integration**: Automatic threat intelligence lookup for IPs and domains
- **AI-Powered Chat**: Ask questions about network traffic in natural language using Ollama LLMs
- **Vector Search**: Efficient similarity search through ChromaDB for Option 2 analysis
- **Agentic Analysis**: Option 3 uses LLM reasoning to generate and execute custom TShark commands for any query
- **Persistent Storage**: All analyses, chat history, and results stored in Supabase
- **Web Interface**: Simple, intuitive UI for uploading files and chatting with the AI analyst

## Architecture

```
┌─────────────────┐
│  Web Frontend   │
└────────┬────────┘
         │
    ┌────▼────┐
    │ FastAPI │
    │ Backend │
    └────┬────┘
         │
    ┌────┴─────────────────────────────┐
    │                                   │
┌───▼──────┐  ┌──────────┐  ┌─────────▼────┐
│ PyShark  │  │ Ollama   │  │  VirusTotal  │
│ Parser   │  │ LLM/Emb  │  │  API Client  │
└───┬──────┘  └────┬─────┘  └──────┬───────┘
    │              │                 │
    └──────┬───────┴─────────────────┘
           │
    ┌──────▼────────────────────┐
    │    Supabase Database      │
    │    ChromaDB Vector Store  │
    └───────────────────────────┘
```

## Prerequisites

- Python 3.8+
- Ollama instance running at http://130.232.102.188:11434
- VirusTotal API key
- Supabase account (configured in .env)
- tshark/Wireshark installed (required by pyshark)

### Installing tshark

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install tshark
```

**macOS:**
```bash
brew install wireshark
```

**Windows:**
Download and install Wireshark from https://www.wireshark.org/download.html

## Installation

1. Clone the repository:
```bash
git clone <your-repo-url>
cd pcap-llm
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure environment variables in `.env`:
```bash
# Supabase Configuration
SUPABASE_URL=your_supabase_url
SUPABASE_KEY=your_supabase_anon_key

# Ollama Configuration
OLLAMA_BASE_URL=http://130.232.102.188:11434
OLLAMA_EMBEDDING_MODEL=nomic-embed-text
OLLAMA_LLM_MODEL=llama3.2

# VirusTotal Configuration
VIRUSTOTAL_API_KEY=your_virustotal_api_key
```

## Usage

### Starting the Server

```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Or use the built-in runner:
```bash
python -m app.main
```

The web interface will be available at: http://localhost:8000

### API Endpoints

- `GET /` - Web interface
- `GET /health` - Health check for all services
- `POST /upload` - Upload PCAP file
- `POST /analyze` - Start analysis (Option 1 or Option 2)
- `GET /status/{analysis_id}` - Check analysis status
- `POST /chat` - Query the AI analyst
- `GET /analysis/{analysis_id}/results` - Get full analysis results
- `GET /analyses` - List all analyses
- `GET /analysis/{analysis_id}/chat_history` - Get chat history

### Analysis Modes

#### Option 1: Summary Chat
- Fast processing
- Creates compact JSON summary with top flows, protocols, HTTP sessions
- Ideal for quick threat assessment and overview
- Lower resource usage

#### Option 2: Full Context Chat (RAG)
- Comprehensive processing
- Converts entire PCAP to detailed JSON
- Creates vector embeddings for similarity search
- Enables deep packet-level queries
- Higher accuracy for complex questions

#### Option 3: Agentic TShark (NEW!)
- AI-powered dynamic analysis
- LLM analyzes your question and decides what TShark commands to run
- Executes custom TShark filters on-demand based on query
- Can run multiple commands iteratively to answer complex questions
- Provides both technical details and natural language interpretation
- Can suggest TShark commands when asked "how do I query..."
- Requires TShark installation
- Best for specific, targeted investigations not covered by summary data

### Example Queries

Once analysis is complete, you can ask questions like:

**All Modes:**
- "What are the top protocols in this capture?"
- "Are there any malicious IPs or domains?"
- "Show me all HTTP requests to suspicious domains"
- "What traffic patterns indicate potential threats?"
- "Summarize the DNS queries"
- "Which IPs communicated most frequently?"

**Option 3 Specific (Agentic TShark):**
- "Show me all traffic to IP 192.168.1.100 on port 443"
- "What DNS queries were made for domain example.com?"
- "Find all TCP retransmissions in this capture"
- "Show HTTP requests with status code 404"
- "What command should I run to find all ICMP packets?"
- "Display all traffic between 10.0.0.1 and 10.0.0.2"

## Project Structure

```
pcap-llm/
├── app/
│   ├── main.py                 # FastAPI application
│   ├── config.py               # Configuration management
│   └── modules/
│       ├── pcap_parser.py      # PCAP file parsing
│       ├── virustotal_client.py # VirusTotal API integration
│       ├── text_chunker.py     # Text chunking for embeddings
│       ├── ollama_client.py    # Ollama LLM/embedding client
│       ├── vector_store.py     # ChromaDB management
│       ├── supabase_client.py  # Supabase database operations
│       ├── pipeline.py         # Analysis pipeline orchestration
│       ├── chat_handler.py     # Chat query handling
│       ├── tshark_executor.py  # TShark command execution (Option 3)
│       └── tshark_agent.py     # Agentic TShark decision engine (Option 3)
├── frontend/
│   └── index.html              # Web interface
├── data/
│   ├── uploads/                # Uploaded PCAP files
│   ├── json_outputs/           # Generated JSON files
│   └── vector_db/              # ChromaDB storage
├── requirements.txt
├── .env
└── README.md
```

## Database Schema

The tool uses Supabase with the following tables:

- **pcap_analyses**: Main analysis records with metadata
- **virustotal_results**: Threat intelligence results
- **chat_sessions**: Chat history and responses
- **chunks_metadata**: Text chunks for Option 2 analyses

## Troubleshooting

### Ollama Connection Failed
- Ensure Ollama is running at 
- Test connection: `curl http://IP/api/tags`
- Verify firewall rules allow connections

### VirusTotal Rate Limits
- Free API key allows 4 requests per minute
- The tool automatically adds 15-second delays between queries
- Consider upgrading to premium API for faster processing

### PyShark Errors
- Ensure tshark is installed and in PATH
- On Linux, you may need to run: `sudo usermod -aG wireshark $USER`
- Try running as root if permission issues persist

### ChromaDB Issues
- Delete the `data/vector_db/` directory and restart if corrupted
- Ensure sufficient disk space for vector storage

## Performance Considerations

- **Option 1**: Can process 100MB PCAP in ~2-5 minutes
- **Option 2**: Processing time depends on packet count (~5-15 minutes for 100MB)
- VirusTotal queries are the main bottleneck due to rate limits
- Consider limiting unique IPs/domains queried for large captures

## Security Notes

- Never commit .env file with API keys
- VirusTotal API key should be kept confidential
- PCAP files may contain sensitive network data
- Use appropriate access controls in production

## Contributing

Contributions are welcome! Please ensure:
- Code follows existing style and structure
- New features include appropriate error handling
- Documentation is updated for significant changes

## License

MIT License

## Acknowledgments

- [Ollama](https://ollama.ai/) for local LLM inference
- [VirusTotal](https://www.virustotal.com/) for threat intelligence
- [ChromaDB](https://www.trychroma.com/) for vector storage
- [Supabase](https://supabase.com/) for database services
- [PyShark](https://github.com/KimiNewt/pyshark) for PCAP parsing
