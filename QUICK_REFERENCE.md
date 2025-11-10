# Quick Reference Guide - PCAP LLM Analyzer Improvements

## What Was Fixed

### 1. 🤖 Interactive Chat - NOW WORKS!
**Problem**: Chatbot gave same robotic response regardless of input.
**Solution**: Added intelligent query classification and conversational AI.

**Try These Now:**
- "hi" or "hello" → Get a friendly greeting
- "what can you do?" → See all capabilities
- "give me a summary" → Get overview of analysis
- "what malicious IPs were found?" → Specific threat info
- "tell me about HTTP traffic" → Protocol analysis

### 2. 📊 Full JSON Conversion - ENHANCED!
**Problem**: Option 2 wasn't converting complete packet data.
**Solution**: Captures ALL protocol details now.

**Now Includes:**
- TCP flags (SYN, ACK, FIN, etc.)
- HTTP status codes
- DNS query-response pairs
- TLS/SSL handshake details
- ICMP types and codes
- Packet payloads
- All protocol layers

### 3. 🛡️ File Hash Analysis - NEW FEATURE!
**Problem**: Only IPs/domains were checked in VirusTotal.
**Solution**: PCAP file hash is now analyzed for malware.

**New Intelligence:**
- File malware detection (70+ AV engines)
- Threat classification and family names
- Sandbox verdicts
- Detection timeline (first/last seen)
- Separate file threats from network threats

---

## Quick Test Guide

### Test Interactive Chat
```bash
# Start the application
python3 run.py

# In browser (http://localhost:8000):
1. Upload any PCAP file
2. Analyze (Option 1 or 2)
3. Try these queries:
   - "hi" (expect greeting)
   - "help" (expect capability list)
   - "summary" (expect analysis overview)
   - "malicious IPs" (expect threat list)
```

### Test Full JSON Conversion
```bash
# Check console logs during Option 2 analysis:
[PCAP Parser] Starting full JSON conversion...
[PCAP Parser] Processed 100 packets...
[PCAP Parser] Completed processing 500 packets

# Verify JSON file has:
- TCP flags field
- HTTP status_code field
- DNS answer field
- TLS handshake_type field
```

### Test File Hash Analysis
```bash
# After analysis completes, in chat ask:
"Was the file flagged as malicious?"
"What did VirusTotal say about the file hash?"

# Check database:
# virustotal_results table should have entry with:
# - entity_type = 'file'
# - threat_label, detection_engines, sandbox_verdicts
```

---

## New Files Created

1. **app/modules/query_classifier.py**
   - Classifies user queries into intents
   - Detects greetings, help requests, analysis queries
   - Used by chat handler

2. **IMPROVEMENTS_SUMMARY.md**
   - Detailed documentation of all changes
   - Architecture diagrams
   - Testing scenarios

3. **supabase/migrations/add_file_hash_detection_fields.sql**
   - Database schema for file analysis
   - 11 new fields in virustotal_results table

---

## Key Code Changes

### Query Classification
```python
# New in chat_handler.py
query_classification = self.query_classifier.classify_query(query)

if query_classification['type'] == 'greeting':
    return self._handle_greeting_query(analysis_id, query)
```

### File Hash Query
```python
# Updated in pipeline.py
file_hash = summary['file_info']['file_hash']
vt_results = self.vt_client.batch_query_entities(ips, domains, [file_hash])
```

### Enhanced Packet Data
```python
# New in pcap_parser.py
packet_data['tcp'] = {
    'src_port': packet.tcp.srcport,
    'dst_port': packet.tcp.dstport,
    'flags': packet.tcp.flags,  # NEW!
    'seq': packet.tcp.seq,      # NEW!
    'ack': packet.tcp.ack       # NEW!
}
```

---

## Expected Behavior Examples

### Example 1: Natural Conversation
```
User: "hi"
AI: "Hello! I'm your network security analyst assistant. I've analyzed
     your PCAP file and I'm ready to help you understand the network
     traffic, identify threats, and answer any questions. What would
     you like to know?"

User: "what can you do?"
AI: "I can help you with various aspects of network traffic analysis:
     - Provide summaries
     - Identify malicious IPs and domains
     - Analyze protocols
     - Answer specific questions
     [Full capability list shown]"

User: "give me a summary"
AI: [Provides concise overview of the capture with key findings]

User: "any malicious IPs?"
AI: [Lists specific IPs flagged by VirusTotal with detection counts]
```

### Example 2: File Hash Detection
```
User: "was the file itself malicious?"
AI: "Yes, the PCAP file hash was flagged by VirusTotal.
     Detection: 35/70 antivirus engines identified it as malicious.
     Threat Classification: Trojan.Generic.Win32
     Top Detections:
     - Kaspersky: Trojan.Win32.Malware
     - Microsoft: Trojan:Win32/Agent
     - Symantec: Trojan.Gen.2"
```

### Example 3: Complete Packet Analysis
```
User: "show me TCP connections with SYN flag"
AI: [RAG retrieves chunks with TCP flag information]
    "Found several TCP SYN packets in the capture:
     - 192.168.1.50:52341 -> 10.0.0.1:443 [Flags: S]
     - 192.168.1.50:52342 -> 10.0.0.1:80 [Flags: S]
     These represent connection initiation attempts..."
```

---

## Troubleshooting

### Issue: Chat still robotic
**Check**: Make sure query_classifier.py is in app/modules/
**Fix**: Restart application to reload modules

### Issue: Full JSON missing fields
**Check**: Console logs during parsing
**Verify**: JSON file has 'tcp', 'http', 'dns', 'tls' objects with sub-fields
**Fix**: Ensure pyshark has access to all packet layers

### Issue: File hash not queried
**Check**: VirusTotal rate limiting logs
**Verify**: Database has virustotal_results with entity_type='file'
**Fix**: Check VirusTotal API key is valid

### Issue: Vector search returns no results
**Check**: Chunks were created and embedded
**Verify**: Collection exists in ChromaDB
**Fix**: Increase chunk size or adjust query

---

## Performance Notes

- **File hash queries**: Count against VirusTotal rate limit (4 requests/min free tier)
- **Full JSON conversion**: May take longer for large PCAP files (100k+ packets)
- **Vector embedding**: Option 2 takes ~2-3x longer than Option 1 due to embedding
- **Chat response time**: ~5-15 seconds depending on LLM model and context size

---

## API Rate Limits

### VirusTotal Free Tier
- 4 requests per minute
- 500 requests per day
- System automatically applies 15-second delay between requests

**Query Order:**
1. File hash (1 request)
2. Up to 50 IPs (50 requests max)
3. Up to 50 domains (50 requests max)

**Recommendation**: For large PCAP files with many unique IPs/domains, consider reducing the limit in pipeline.py:
```python
ips = summary['unique_entities']['ips'][:20]  # Reduce from 50 to 20
domains = summary['unique_entities']['domains'][:20]
```

---

## Database Schema

### New Fields in `virustotal_results`
```sql
-- File-specific fields (only populated for entity_type='file')
file_type              text        -- "PE32 executable", "ZIP archive", etc.
file_size              bigint      -- Size in bytes
threat_label           text        -- "Trojan.Generic", "Ransomware.Locky"
threat_category        jsonb       -- ["trojan", "backdoor"]
detection_engines      jsonb       -- [{engine, category, result}]
sandbox_verdicts       jsonb       -- [{sandbox, category, malware_names}]
md5                    text        -- MD5 hash
sha1                   text        -- SHA1 hash
sha256                 text        -- SHA256 hash
first_submission_date  timestamptz -- When first seen in VT
last_analysis_date     timestamptz -- Most recent analysis
```

---

## What to Expect

### Startup
```
[PCAP Parser] Starting full JSON conversion...
[PCAP Parser] Processed 100 packets...
[VirusTotal] Starting batch query: 1 file hashes, 25 IPs, 15 domains
[VirusTotal] Querying file hash 1/1: abc123def456...
[Vector Store] Processing 45 chunks in 1 batches
```

### During Chat
```
[Chat Handler] Query classified as: greeting - greet
[Chat Handler] Query classified as: specific - analyze
[Vector Store] Starting similarity search...
[Ollama LLM] Sending generation request...
[Ollama LLM] Generation complete (length: 543 chars)
```

---

## Success Indicators

✅ Greetings get friendly responses (not analysis)
✅ Help queries return capability list
✅ Summary requests provide overview
✅ Specific questions get precise answers
✅ Full JSON has all protocol fields
✅ File hash appears in VirusTotal results
✅ Separate file threats from network threats in chat
✅ Console shows progress logs
✅ Database has new file-specific columns

---

## Support & Debugging

### Enable Verbose Logging
All modules already include print statements for debugging. Watch console for:
- `[PCAP Parser]` - File parsing progress
- `[VirusTotal]` - API query status
- `[Chat Handler]` - Query classification
- `[Vector Store]` - Embedding and search operations
- `[Ollama LLM]` - Generation requests and responses

### Check Database
Use Supabase dashboard to verify:
1. `pcap_analyses` table has your analysis record
2. `virustotal_results` has entries for file, IPs, domains
3. `chat_sessions` stores conversation history
4. `chunks_metadata` has chunk records (Option 2 only)

### Verify Vector Database
```python
# In Python console
from app.modules.vector_store import VectorStoreManager
vs = VectorStoreManager('./data/vector_db', 'http://localhost:11434', 'nomic-embed-text')
print(vs.list_collections())  # Should show pcap_{analysis_id} collections
```

---

## Quick Commands

```bash
# Start application
python3 run.py

# Check syntax of all modules
python3 -m py_compile app/modules/*.py

# Test query classifier
python3 -c "from app.modules.query_classifier import QueryClassifier; qc = QueryClassifier(); print(qc.classify_query('hello'))"

# Verify database connection
python3 verify_setup.py

# View application logs
# (Watch console where you ran python3 run.py)
```

---

## Summary

**What Changed**:
- Interactive conversational AI with intent detection
- Complete packet data capture in full JSON mode
- VirusTotal file hash malware analysis
- Enhanced vector database chunks
- Improved chat context formatting

**How to Use**:
1. Start app: `python3 run.py`
2. Upload PCAP file
3. Choose analysis mode
4. Chat naturally: greetings, questions, follow-ups
5. Ask about file threats specifically
6. Explore deep packet details (Option 2)

**Result**:
Natural, intelligent security analysis assistant that understands conversation, captures complete network data, and provides comprehensive threat intelligence including file-level malware detection.

🎉 **Enjoy your enhanced PCAP LLM Analyzer!**
