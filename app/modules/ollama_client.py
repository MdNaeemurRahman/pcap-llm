import requests
import json
from typing import Dict, List, Any, Optional
from .optimized_prompts import get_option1_prompt, get_option2_prompt, get_option3_prompt


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

        prompt_parts.append("=== PRE-ANALYZED PCAP SUMMARY DATA ===")
        prompt_parts.append("(This is a comprehensive summary created from detailed PCAP analysis)")
        prompt_parts.append(context)
        prompt_parts.append("")
        prompt_parts.append(f"=== USER QUESTION ===")
        prompt_parts.append(query)
        prompt_parts.append("")
        prompt_parts.append("=== INSTRUCTIONS ===")
        prompt_parts.append("- Answer the question using ONLY information from the summary above")
        prompt_parts.append("- Be concise and direct - match response length to question complexity")
        prompt_parts.append("- Cite specific evidence from the summary (IP addresses, packet counts, domains)")
        prompt_parts.append("- For threats, reference VirusTotal findings explicitly")
        prompt_parts.append("- If information is not in the summary, say so clearly")
        prompt_parts.append("- NEVER invent or assume details not present in the summary")

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
        prompt_parts.append("- Answer ONLY the specific question asked - be direct and concise")
        prompt_parts.append("- Match response length to question complexity (simple question = short answer)")
        prompt_parts.append("- CORRELATE findings between network traffic and threat intelligence when relevant")
        prompt_parts.append("- CITE specific evidence: packet ranges, timestamps, IPs, domains")
        prompt_parts.append("- When discussing threats, CLEARLY indicate they come from VirusTotal analysis")
        prompt_parts.append("- MAINTAIN conversational continuity - remember what was discussed previously")
        prompt_parts.append("- If you don't have the information requested, say so directly - don't make things up")
        prompt_parts.append("- Use NATURAL language - avoid phrases like 'Chunk 1' or 'from the chunks'")
        prompt_parts.append("")
        prompt_parts.append("CRITICAL: Keep your response concise and focused on answering the question. Don't provide unnecessary background information or summaries unless specifically asked.")

        return "\n".join(prompt_parts)

    def get_system_prompt(self) -> str:
        """System prompt specifically for Option 1 - Summary-based analysis."""
        return get_option1_prompt()

    def get_option2_system_prompt(self) -> str:
        return get_option2_prompt()

    def get_option3_system_prompt(self) -> str:
        return get_option3_prompt()

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
