# Option 3: Agentic Reasoning with Conversational Memory

## Overview

Option 3 has been completely redesigned to use **true agentic AI reasoning** with **multi-step thinking** and **conversational memory**. The system no longer relies on predefined templates or pattern matching. Instead, it uses an LLM-powered reasoning engine that thinks through each query step-by-step, maintains conversation context, and dynamically determines the best analysis approach.

## Architecture

### Core Components

1. **ConversationMemory** (`app/modules/conversation_memory.py`)
   - Maintains short-term memory across conversation exchanges
   - Tracks discovered entities (IPs, domains, credentials, etc.)
   - Resolves contextual references ("this ip", "that user", "the password")
   - Stores analysis results cache to avoid redundant TShark executions

2. **ReasoningEngine** (`app/modules/reasoning_engine.py`)
   - Multi-step reasoning pipeline for query processing
   - Dynamic intent analysis using LLM
   - Context-aware command planning
   - Natural language interpretation of results

3. **TSharkAgent** (`app/modules/tshark_agent.py`)
   - Orchestrates the agentic workflow
   - Integrates memory and reasoning engine
   - Executes TShark commands based on LLM reasoning
   - Extracts and stores discovered entities

4. **ChatHandler** (`app/modules/chat_handler.py`)
   - Manages per-analysis-session agent instances
   - Maintains persistent memory for each conversation
   - Handles routing between options

## How It Works: Multi-Step Reasoning Pipeline

When a user asks a question in Option 3, the system goes through these steps:

### Step 1: Query Intent Analysis
```python
intent = reasoning_engine.analyze_query_intent(user_query, pcap_summary)
```

The LLM analyzes:
- What type of query is this? (investigation, overview, follow-up, greeting, command request)
- Does it reference previous conversation context?
- Can it be answered from summary data alone?
- What entities are mentioned (IPs, domains, users, etc.)?
- What approach should be taken?

**Example:**
```
User: "what was the password of that user?"

Intent Analysis:
{
  "query_type": "follow_up",
  "references_previous_context": true,
  "can_answer_from_summary": false,
  "needs_dynamic_analysis": true,
  "entities_mentioned": ["password", "user"],
  "reasoning": "User asking about password related to previously mentioned user",
  "approach": "execute tshark to extract FTP password"
}
```

### Step 2: Check Summary Data & Memory
```python
answer = reasoning_engine.check_summary_for_answer(query, pcap_summary, intent)
```

The LLM checks if the answer exists in:
- PCAP summary statistics
- VirusTotal threat intelligence
- Conversation memory from previous exchanges
- Cached analysis results

If found, returns answer immediately without TShark execution.

### Step 3: Plan Dynamic Analysis
```python
plan_result = reasoning_engine.plan_dynamic_analysis(query, pcap_summary, intent)
```

The LLM reasons about:
- What specific information needs to be extracted?
- What TShark filters will retrieve this data?
- What protocol-specific fields to extract?
- What sequence of commands to execute?

**Example for password extraction:**
```json
{
  "reasoning": "User wants FTP password. Need to filter FTP PASS commands and extract the argument.",
  "commands": [
    {
      "command_args": ["-T", "fields", "-e", "ftp.request.arg", "-Y", "ftp.request.command == PASS"],
      "purpose": "Extract FTP password from PASS command",
      "expected_output": "Password value",
      "extracts": "FTP password credentials"
    }
  ]
}
```

### Step 4: Execute TShark Commands
```python
result = executor.execute_custom_command(pcap_file_path, command_args)
```

The system executes the planned TShark commands and captures output.

### Step 5: Interpret Results
```python
interpretation = reasoning_engine.interpret_analysis_results(query, results, intent)
```

The LLM:
- Processes raw TShark output
- Extracts relevant information
- Formulates natural, conversational response
- Cites specific evidence found
- Explains what the findings mean

**Example interpretation:**
```
"I found the FTP password used by user 'ben@ercolina-usa.com'. The password is 'secretpass123'.
This credential was transmitted in cleartext in packet #27 during the FTP authentication sequence
with IP 192.254.225.136 on port 21."
```

### Step 6: Extract & Store Entities
```python
discovered = reasoning_engine.extract_discovered_entities(results)
memory.add_exchange(query, response, reasoning, commands, discovered)
```

The system:
- Extracts discovered entities from results (IPs, passwords, etc.)
- Stores them in conversation memory
- Makes them available for future queries
- Builds a knowledge graph of the session

## Conversation Memory Features

### Reference Resolution

The system automatically resolves contextual references:

```python
User: "which ip downloading files?"
AI: "IP 192.254.225.136 was involved in file transfers."

User: "is this ip downloading any files?"
# Resolved to: "is 192.254.225.136 downloading any files?"

User: "what was the password of that user?"
# Resolved to: "what was the password related to the user mentioned earlier?"
```

### Entity Tracking

Discovered entities are tracked throughout the conversation:

```python
memory.discovered_entities = {
    'ips': ['192.254.225.136', '10.12.4.101'],
    'domains': ['example.com'],
    'protocols': ['FTP', 'HTTP'],
    'credentials': [
        {'type': 'username', 'value': 'ben@ercolina-usa.com'},
        {'type': 'password', 'value': 'secretpass123'}
    ],
    'connections': [...],
    'file_transfers': [...]
}
```

### Context Injection

Every query includes conversation history:

```
=== CONVERSATION MEMORY ===
Session started: 2024-11-11T10:30:00
Total exchanges: 3

--- Exchange 1 ---
USER ASKED: which ip downloading files?
YOU RESPONDED: IP 192.254.225.136 was involved in file transfers via FTP...
DISCOVERED: {"ips": ["192.254.225.136"], "protocols": ["FTP"]}

--- Exchange 2 ---
USER ASKED: is this ip downloading any files?
YOU RESPONDED: Yes, user 'ben@ercolina-usa.com' authenticated via FTP...
DISCOVERED: {"credentials": [{"type": "username", "value": "ben@ercolina-usa.com"}]}
```

## Protocol-Specific Analysis

The system now has enhanced knowledge of protocol-specific analysis:

### FTP Analysis
```
- Extract usernames: ftp.request.command == USER
- Extract passwords: ftp.request.command == PASS
- Find downloads: ftp.request.command == RETR
- Find uploads: ftp.request.command == STOR
- Get arguments: ftp.request.arg
```

### HTTP Analysis
```
- Extract downloads: http.request.method == GET
- Get hosts: http.host
- Get URIs: http.request.uri
- Response codes: http.response.code
```

### DNS Analysis
```
- Query names: dns.qry.name
- Filter queries: dns.flags.response == 0
- Filter responses: dns.flags.response == 1
```

## Testing Your Conversation Scenario

Your exact conversation now works correctly:

```
1. User: "which ip downloading files?"
   → AI analyzes traffic, finds 192.254.225.136 with FTP activity
   → Stores IP in memory

2. User: "is this ip downloading any files?"
   → AI resolves "this ip" to 192.254.225.136 from memory
   → Executes: tshark -Y "ip.addr == 192.254.225.136 && ftp"
   → Finds FTP traffic with user 'ben@ercolina-usa.com'
   → Stores username in memory

3. User: "what was the password of that authenticated user?"
   → AI understands "that user" refers to 'ben@ercolina-usa.com'
   → Plans command: -T fields -e ftp.request.arg -Y "ftp.request.command == PASS"
   → Executes TShark to extract password
   → Returns: "The password for user 'ben@ercolina-usa.com' is [password]"

4. User: "what was the password of this user 'ben@ercolina-usa.com'?"
   → Same as #3, directly extracts FTP password
   → No template response - actual dynamic analysis
```

## Key Improvements Over Old System

### Before (Template-Based)
```python
# Hardcoded pattern matching
if 'password' in query_lower:
    return "I searched but didn't find any matching data."
```

### After (Agentic Reasoning)
```python
# LLM reasons about what to do
intent = analyze_query_intent(query)
plan = plan_dynamic_analysis(query, intent)
results = execute_commands(plan)
answer = interpret_results(results, intent)
```

## Running Tests

```bash
# Test conversation memory
python3 test_option3_reasoning.py

# Or test individual components
python3 -c "from app.modules.conversation_memory import ConversationMemory; ..."
```

## Memory Management

Each analysis session has its own agent with persistent memory:

```python
# Memory persists across queries within same session
agent = chat_handler._get_or_create_option3_agent(analysis_id)

# Clear specific session
chat_handler.clear_option3_memory(analysis_id)

# Clear all sessions (memory management)
chat_handler.clear_all_option3_memories()
```

## Benefits

1. **No More Templates**: Every response comes from LLM reasoning
2. **Contextual Awareness**: Understands follow-up questions
3. **Entity Tracking**: Remembers discovered information
4. **Dynamic Planning**: Determines analysis approach per query
5. **Natural Conversation**: Maintains flow like talking to human analyst
6. **Protocol Intelligence**: Deep knowledge of FTP, HTTP, DNS, etc.
7. **Multi-Step Reasoning**: Plans → Executes → Interprets → Responds

## Future Enhancements

- [ ] Add result caching to avoid re-executing identical commands
- [ ] Implement conversation summarization for very long sessions
- [ ] Add ability to export conversation memory to database
- [ ] Create visualization of discovered entity relationships
- [ ] Add support for multi-file PCAP analysis with shared memory
