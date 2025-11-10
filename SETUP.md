# PCAP LLM Analyzer - Setup Guide

This guide will walk you through setting up the PCAP LLM Analyzer on your local machine.

## Quick Start

1. **Install Python dependencies:**
```bash
pip install -r requirements.txt
```

2. **Configure your environment:**
- Copy `.env.example` to `.env` (if not already done)
- Update `VIRUSTOTAL_API_KEY` with your actual API key

3. **Verify your setup:**
```bash
python verify_setup.py
```

4. **Start the server:**
```bash
python run.py
```

5. **Access the web interface:**
Open your browser to http://localhost:8000

---

## Detailed Setup Instructions

### Step 1: System Prerequisites

#### Install tshark/Wireshark

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install tshark

# Add your user to wireshark group (optional, for non-root access)
sudo usermod -aG wireshark $USER
# Log out and back in for changes to take effect
```

**macOS:**
```bash
brew install wireshark
```

**Windows:**
1. Download Wireshark from https://www.wireshark.org/download.html
2. Run the installer
3. Make sure "TShark" is selected during installation
4. Add Wireshark to your PATH

#### Verify tshark installation:
```bash
tshark -v
```

### Step 2: Python Environment Setup

1. **Create a virtual environment (recommended):**
```bash
python -m venv venv

# Activate the virtual environment
# On Linux/Mac:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

2. **Install Python dependencies:**
```bash
pip install -r requirements.txt
```

### Step 3: Configure Services

#### A. VirusTotal API Key

1. Sign up for a free account at https://www.virustotal.com/
2. Navigate to your API key: https://www.virustotal.com/gui/user/YOUR_USERNAME/apikey
3. Copy your API key
4. Update `.env` file:
```bash
VIRUSTOTAL_API_KEY=your_actual_api_key_here
```

**Note:** Free tier allows 4 requests per minute with a daily limit. The application automatically rate-limits to 1 request per 15 seconds.

#### B. Ollama Configuration

The Ollama instance is already configured to run at:
```
http://130.232.102.188:11434
```

You can verify the connection:
```bash
curl http://130.232.102.188:11434/api/tags
```

If you need to change the Ollama server, update `.env`:
```bash
OLLAMA_BASE_URL=http://your-ollama-server:11434
OLLAMA_EMBEDDING_MODEL=nomic-embed-text
OLLAMA_LLM_MODEL=llama3.2
```

#### C. Supabase Configuration

Your Supabase database is already configured in the `.env` file. The database schema has been automatically created with the following tables:
- `pcap_analyses` - Stores PCAP analysis metadata
- `virustotal_results` - Stores threat intelligence results
- `chat_sessions` - Stores chat history
- `chunks_metadata` - Stores text chunks for Option 2 analysis

No additional Supabase configuration is needed!

### Step 4: Verify Setup

Run the verification script to check all components:

```bash
python verify_setup.py
```

This will check:
- ✓ Python version (3.8+)
- ✓ Python dependencies installed
- ✓ TShark installation
- ✓ Environment file configuration
- ✓ Data directories
- ✓ Ollama connection

### Step 5: Start the Application

**Option 1: Using the run script (recommended)**
```bash
python run.py
```

**Option 2: Using uvicorn directly**
```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**Option 3: With auto-reload for development**
```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

The server will start at: **http://localhost:8000**

---

## Usage Workflow

### 1. Upload a PCAP File
- Click the upload zone or drag and drop your .pcap/.pcapng/.cap file
- The file will be uploaded and its hash computed
- If the file was previously analyzed, you'll see the existing results

### 2. Choose Analysis Mode

**Option 1: Summary Chat** (Recommended for quick analysis)
- Fast processing (2-5 minutes for 100MB PCAP)
- Creates a compact summary with top flows and protocols
- Best for threat assessment and overview
- Lower resource usage

**Option 2: Full Context Chat** (For deep investigation)
- Comprehensive processing (5-15 minutes for 100MB PCAP)
- Analyzes every packet in detail
- Creates vector embeddings for intelligent search
- Best for complex queries and detailed investigation
- Higher resource usage

### 3. Wait for Analysis
The status will update through these stages:
- **uploaded** → **parsing** → **enriching** → **embedding** (Option 2 only) → **ready**

You'll see:
- Total packets analyzed
- Unique IPs and domains found
- Protocol distribution
- Progress updates

### 4. Chat with AI Analyst

Once analysis is **ready**, you can ask questions like:

**General Analysis:**
- "What are the top protocols in this capture?"
- "Summarize the network traffic"
- "What domains were accessed?"

**Security-Focused:**
- "Are there any malicious IPs or domains?"
- "Show me suspicious traffic"
- "What IPs have been flagged by VirusTotal?"
- "Are there any security threats?"

**Protocol-Specific:**
- "Show me all HTTP requests"
- "What DNS queries were made?"
- "List all TLS/SSL connections"

**Investigation:**
- "Which IP communicated most frequently?"
- "Show traffic to external servers"
- "What happened between 10:00 and 11:00?"

---

## File Structure

After setup, your directory structure will look like:

```
pcap-llm/
├── .env                        # Your configuration (DO NOT COMMIT)
├── .env.example                # Example configuration
├── .gitignore                  # Git ignore rules
├── Readme.md                   # Main documentation
├── SETUP.md                    # This file
├── requirements.txt            # Python dependencies
├── run.py                      # Application launcher
├── verify_setup.py             # Setup verification script
│
├── app/                        # Application code
│   ├── __init__.py
│   ├── main.py                 # FastAPI application
│   ├── config.py               # Configuration management
│   └── modules/                # Core modules
│       ├── pcap_parser.py      # PCAP parsing
│       ├── virustotal_client.py # VirusTotal integration
│       ├── text_chunker.py     # Text chunking
│       ├── ollama_client.py    # Ollama API client
│       ├── vector_store.py     # ChromaDB management
│       ├── supabase_client.py  # Supabase operations
│       ├── pipeline.py         # Analysis pipeline
│       └── chat_handler.py     # Chat functionality
│
├── frontend/                   # Web interface
│   └── index.html
│
├── data/                       # Application data (gitignored)
│   ├── uploads/                # Uploaded PCAP files
│   ├── json_outputs/           # Generated JSON analyses
│   └── vector_db/              # ChromaDB storage
│
└── supabase/                   # Supabase migrations
    └── migrations/
```

---

## Troubleshooting

### "tshark not found" Error

**Solution:** Install Wireshark/tshark as described in Step 1

### "Permission denied" when running tshark

**Linux Solution:**
```bash
sudo usermod -aG wireshark $USER
# Log out and back in
```

**Alternative:** Run the application as root (not recommended for production)

### "Connection to Ollama failed"

**Check Ollama status:**
```bash
curl http://130.232.102.188:11434/api/tags
```

**Solutions:**
- Verify the Ollama server is running
- Check firewall rules
- Test network connectivity
- Verify the URL in `.env` is correct

### "VirusTotal rate limit exceeded"

**Explanation:** Free API tier allows 4 requests/minute

**Solutions:**
- Wait for rate limit to reset (1 minute)
- Application automatically delays 15 seconds between requests
- Upgrade to premium VirusTotal API for higher limits
- Limit the number of unique IPs/domains in your PCAP

### "ChromaDB error" or vector store issues

**Solution:**
```bash
# Delete ChromaDB data and restart
rm -rf data/vector_db/*
python run.py
```

### "Supabase connection failed"

**Check:**
- `.env` file has correct `SUPABASE_URL` and `SUPABASE_KEY`
- Internet connection is working
- Supabase service is online

### Analysis stuck in "parsing" status

**Possible causes:**
- Very large PCAP file (> 500MB)
- Complex encrypted traffic
- System running out of memory

**Solutions:**
- Try a smaller PCAP file first
- Check system resources (RAM, CPU)
- Restart the application

---

## Performance Tips

1. **For large PCAP files (> 100MB):**
   - Use Option 1 (Summary Chat) for faster results
   - Consider splitting the PCAP into smaller files
   - Ensure sufficient RAM (4GB+ recommended)

2. **Reduce VirusTotal queries:**
   - The application limits to first 50 unique IPs and 50 domains
   - You can modify this in `app/modules/pipeline.py`

3. **Option 2 processing:**
   - Requires more time and resources
   - Best for PCAPs under 100MB
   - Creates embeddings for ~100 packets per chunk

---

## Next Steps

Once your setup is complete:

1. **Test with a small PCAP file** (< 10MB) to verify everything works
2. **Try both analysis modes** to understand the difference
3. **Experiment with different queries** to see what the AI can answer
4. **Check the generated JSON files** in `data/json_outputs/`

## Support

For issues or questions:
1. Check this SETUP.md and README.md
2. Review the Troubleshooting section
3. Verify setup with `python verify_setup.py`
4. Check application logs for error messages

---

**Ready to start?**

```bash
python verify_setup.py  # Verify everything is configured
python run.py          # Start the application
```

Then open http://localhost:8000 in your browser!
