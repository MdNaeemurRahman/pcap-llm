import requests
import json
from typing import Dict, List, Any, Optional


class OllamaClient:
    def __init__(self, base_url: str, embedding_model: str = "nomic-embed-text", llm_model: str = "llama3.2"):
        self.base_url = base_url.rstrip('/')
        self.embedding_model = embedding_model
        self.llm_model = llm_model

    def validate_connection(self) -> bool:
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return response.status_code == 200
        except Exception as e:
            print(f"Failed to connect to Ollama: {str(e)}")
            return False

    def generate_embeddings(self, text: str) -> Optional[List[float]]:
        url = f"{self.base_url}/api/embeddings"
        payload = {
            "model": self.embedding_model,
            "prompt": text
        }

        try:
            print(f"[Ollama Embedding] Sending request to model: {self.embedding_model}")
            response = requests.post(url, json=payload, timeout=30)
            if response.status_code == 200:
                result = response.json()
                embedding = result.get('embedding', [])
                print(f"[Ollama Embedding] Response received: OK (dimensions: {len(embedding)})")
                return embedding
            else:
                print(f"[Ollama Embedding] Request failed: {response.status_code}")
                return None
        except Exception as e:
            print(f"[Ollama Embedding] Error: {str(e)}")
            return None

    def batch_embed_chunks(self, chunks: List[str]) -> List[Optional[List[float]]]:
        embeddings = []
        total = len(chunks)

        print(f"Generating embeddings for {total} chunks...")

        for i, chunk in enumerate(chunks, 1):
            print(f"Processing chunk {i}/{total}...")
            embedding = self.generate_embeddings(chunk)
            embeddings.append(embedding)

        return embeddings

    def generate_llm_response(self, prompt: str, stream: bool = False, system_prompt: Optional[str] = None) -> str:
        url = f"{self.base_url}/api/generate"

        payload = {
            "model": self.llm_model,
            "prompt": prompt,
            "stream": stream
        }

        if system_prompt:
            payload["system"] = system_prompt

        try:
            print(f"[Ollama LLM] Sending generation request to model: {self.llm_model}")
            response = requests.post(url, json=payload, timeout=120)

            if response.status_code == 200:
                print(f"[Ollama LLM] Response received: OK")
                if stream:
                    full_response = ""
                    for line in response.iter_lines():
                        if line:
                            chunk_data = json.loads(line)
                            if 'response' in chunk_data:
                                full_response += chunk_data['response']
                            if chunk_data.get('done', False):
                                break
                    print(f"[Ollama LLM] Streaming complete (length: {len(full_response)} chars)")
                    return full_response
                else:
                    result = response.json()
                    llm_response = result.get('response', '')
                    print(f"[Ollama LLM] Generation complete (length: {len(llm_response)} chars)")
                    return llm_response
            else:
                print(f"[Ollama LLM] Request failed: {response.status_code}")
                return f"Error: LLM generation failed with status {response.status_code}"
        except Exception as e:
            print(f"[Ollama LLM] Error: {str(e)}")
            return f"Error generating LLM response: {str(e)}"

    def format_prompt_for_network_analysis(self, query: str, context: str, chat_history: Optional[List[Dict[str, str]]] = None, analysis_mode: Optional[str] = None) -> str:
        prompt_parts = []

        if chat_history and len(chat_history) > 0:
            prompt_parts.append("=== CONVERSATION HISTORY ===")
            for msg in chat_history[-3:]:
                prompt_parts.append(f"User: {msg['user']}")
                prompt_parts.append(f"Assistant: {msg['assistant'][:200]}...") if len(msg['assistant']) > 200 else prompt_parts.append(f"Assistant: {msg['assistant']}")
            prompt_parts.append("")

        prompt_parts.append("=== NETWORK TRAFFIC ANALYSIS DATA ===")
        prompt_parts.append(context)
        prompt_parts.append("")
        prompt_parts.append(f"=== USER QUESTION ===")
        prompt_parts.append(query)
        prompt_parts.append("")

        if analysis_mode == 'option2':
            prompt_parts.append("Note: The context contains two types of data segments:")
            prompt_parts.append("1. Network Traffic Segments - showing packet-level traffic analysis")
            prompt_parts.append("2. VirusTotal Threat Intelligence Segments - showing confirmed threats from VirusTotal")
            prompt_parts.append("When citing information, reference packet ranges, IP addresses, domains, or timeframes.")
            prompt_parts.append("When discussing threats, clearly indicate whether they come from VirusTotal threat intelligence.")
            prompt_parts.append("Use natural language like 'In packets 100-200' or 'According to VirusTotal threat intelligence' instead of 'Chunk 1' or 'Chunk 2'.")

        return "\n".join(prompt_parts)

    def format_prompt_for_option2_analysis(self, query: str, context: str, chat_history: Optional[List[Dict[str, str]]] = None) -> str:
        prompt_parts = []

        if chat_history and len(chat_history) > 0:
            prompt_parts.append("=== CONVERSATION HISTORY ===")
            for msg in chat_history[-3:]:
                prompt_parts.append(f"User: {msg['user']}")
                if len(msg['assistant']) > 200:
                    prompt_parts.append(f"Assistant: {msg['assistant'][:200]}...")
                else:
                    prompt_parts.append(f"Assistant: {msg['assistant']}")
            prompt_parts.append("")

        prompt_parts.append("=== DUAL-SOURCE CONTEXT FOR ANALYSIS ===")
        prompt_parts.append("You have access to TWO distinct types of information retrieved through similarity search:")
        prompt_parts.append("")
        prompt_parts.append("1. NETWORK TRAFFIC SEGMENTS: Detailed packet-level data from the PCAP file")
        prompt_parts.append("   - Contains timestamps, IPs, domains, protocols, HTTP requests, DNS queries")
        prompt_parts.append("   - Use this to understand WHAT happened in the network traffic")
        prompt_parts.append("   - Reference using: 'In packets X-Y', 'At timestamp Z', 'Traffic between IP A and B'")
        prompt_parts.append("")
        prompt_parts.append("2. VIRUSTOTAL THREAT INTELLIGENCE: Pre-analyzed security threat data")
        prompt_parts.append("   - Contains confirmed malicious/suspicious entities flagged by security vendors")
        prompt_parts.append("   - Use this to understand SECURITY IMPLICATIONS of network entities")
        prompt_parts.append("   - Reference using: 'According to VirusTotal', 'Threat intelligence shows', 'Security vendors flagged'")
        prompt_parts.append("")
        prompt_parts.append("=== RETRIEVED CONTEXT ===")
        prompt_parts.append(context)
        prompt_parts.append("")
        prompt_parts.append("=== USER QUESTION ===")
        prompt_parts.append(query)
        prompt_parts.append("")
        prompt_parts.append("=== ANALYSIS INSTRUCTIONS ===")
        prompt_parts.append("- CORRELATE findings between network traffic and threat intelligence")
        prompt_parts.append("- CITE specific evidence: packet ranges, timestamps, IPs, domains")
        prompt_parts.append("- When discussing threats, CLEARLY indicate they come from VirusTotal analysis")
        prompt_parts.append("- MAINTAIN conversational continuity - remember what was discussed previously")
        prompt_parts.append("- ANSWER the specific question asked - don't just summarize all available data")
        prompt_parts.append("- If the user asks a follow-up, build on the previous conversation")
        prompt_parts.append("- Use NATURAL language - avoid phrases like 'Chunk 1' or 'from the chunks'")

        return "\n".join(prompt_parts)

    def get_system_prompt(self) -> str:
        return """You are an expert network security analyst assistant specializing in PCAP analysis and threat detection. You have access to network traffic data and threat intelligence to help users understand security postures and investigate potential threats.

Core Capabilities:
- Analyze network traffic patterns, protocols, and communication flows
- Identify malicious activities using VirusTotal threat intelligence
- Investigate specific IPs, domains, file hashes, and network behaviors
- Provide security assessments and actionable recommendations
- Explain technical concepts in clear, accessible language

Conversational Approach:
- Respond naturally to any user query - greetings, questions, or requests
- Adapt your response style to match the user's needs (detailed vs. summary)
- Use your expertise to determine what information is most relevant
- If a user asks a simple question, give a simple answer
- For complex investigations, provide comprehensive analysis
- Handle casual conversation professionally while staying focused on security analysis

Analysis Methodology:
- Always cite specific evidence: IP addresses, packet ranges, domains, timestamps
- Highlight threats and suspicious patterns prominently
- Use VirusTotal results as authoritative threat intelligence
- Explain "why" something is significant, not just "what" it is
- Provide context about normal vs. abnormal network behavior
- Offer actionable next steps and security recommendations

Citation Standards:
- Reference specific data points naturally in your explanations
- Use phrases like "Traffic between packets 150-250 shows..." or "The IP 192.168.1.1 exhibits..."
- NEVER use generic references like "Chunk 1" or "from the chunks"
- When multiple pieces of evidence support a finding, cite them all
- If you don't have information to answer a query, say so clearly

Security Focus:
- Prioritize threats and security implications in your analysis
- Distinguish between confirmed threats (VirusTotal flagged) and suspicious patterns
- Explain the potential impact and severity of identified issues
- Provide both technical details and business-level summaries
- Recommend specific mitigation strategies when appropriate

Remember: You are a professional security analyst having a conversation with a colleague. Be knowledgeable, precise, helpful, and conversational. Let your expertise guide your responses naturally without being constrained by rigid response patterns."""

    def get_option2_system_prompt(self) -> str:
        return """You are an expert network security analyst assistant with deep expertise in PCAP analysis and threat intelligence correlation. You work with a specialized RAG (Retrieval-Augmented Generation) system that provides you with two distinct types of context.

Your Context Sources:
1. NETWORK TRAFFIC DATA: Packet-level details from PCAP files including timestamps, IPs, ports, protocols, HTTP requests, DNS queries, and connection states
2. VIRUSTOTAL THREAT INTELLIGENCE: Pre-analyzed security data showing which entities (IPs, domains, file hashes) have been flagged by security vendors as malicious or suspicious

Core Responsibilities:
- Provide INTERACTIVE, CONVERSATIONAL responses that directly answer user questions
- CORRELATE information between network traffic and threat intelligence
- MAINTAIN context across multiple questions in a conversation thread
- CITE specific evidence from both data sources naturally and precisely
- Explain WHEN events occurred using timestamps, WHAT happened in the traffic, and WHY it's significant from a security perspective

Conversational Approach:
- Treat each query as part of an ongoing conversation with a security colleague
- Remember what was discussed previously and build on that context
- If a user asks a follow-up question, reference and expand on earlier findings
- Answer the SPECIFIC question asked - don't summarize everything you see
- Be concise when the question is simple, detailed when investigating complex threats
- Handle casual greetings naturally while staying focused on security analysis

Evidence Citation Standards:
- For network traffic: "In packets 150-250...", "At timestamp 2024-11-10 14:23:15...", "Traffic between 192.168.1.100 and 10.0.0.50..."
- For threat intelligence: "According to VirusTotal analysis...", "Security vendors flagged...", "Threat intelligence confirms..."
- NEVER use generic references like "Chunk 1", "the chunks", or "retrieved segments"
- When correlating, connect timeline evidence: "The connection to 185.220.100.X was established at 14:23:15, and VirusTotal confirms this IP is flagged by 23 security vendors as a known C2 server"

Analysis Methodology:
- Prioritize ANSWERING the user's question over providing comprehensive summaries
- Use your security expertise to identify patterns that indicate threats
- Explain the significance and potential impact of findings
- Distinguish between confirmed threats (VirusTotal flagged) and suspicious patterns
- Provide actionable insights and recommend next investigation steps when appropriate
- If you don't have relevant information to answer a question, say so clearly

Temporal Analysis Excellence:
- Always note WHEN events occurred if timestamps are available
- Identify sequences of events and their security implications
- Correlate timing of connections with threat intelligence findings
- Help users understand attack timelines and progression

Remember: You're an interactive security analyst having a real conversation. Be natural, be precise, cite your evidence, maintain context, and answer what's asked. Your goal is to help the user understand their network traffic and identify security issues through intelligent analysis of both packet data and threat intelligence."""

    def handle_streaming_response(self, prompt: str, system_prompt: Optional[str] = None):
        url = f"{self.base_url}/api/generate"

        payload = {
            "model": self.llm_model,
            "prompt": prompt,
            "stream": True
        }

        if system_prompt:
            payload["system"] = system_prompt

        try:
            response = requests.post(url, json=payload, stream=True, timeout=120)

            if response.status_code == 200:
                for line in response.iter_lines():
                    if line:
                        chunk_data = json.loads(line)
                        if 'response' in chunk_data:
                            yield chunk_data['response']
                        if chunk_data.get('done', False):
                            break
            else:
                yield f"Error: LLM generation failed with status {response.status_code}"
        except Exception as e:
            yield f"Error generating LLM response: {str(e)}"
