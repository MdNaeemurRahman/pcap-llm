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

    def format_prompt_for_network_analysis(self, query: str, context: str, chat_history: Optional[List[Dict[str, str]]] = None, query_classification: Optional[Dict[str, Any]] = None) -> str:
        prompt_parts = []

        if chat_history and len(chat_history) > 0:
            prompt_parts.append("Previous conversation context:")
            for msg in chat_history[-3:]:
                prompt_parts.append(f"User: {msg['user']}")
                prompt_parts.append(f"Assistant: {msg['assistant'][:200]}...") if len(msg['assistant']) > 200 else prompt_parts.append(f"Assistant: {msg['assistant']}")
            prompt_parts.append("")

        if query_classification and not query_classification['requires_context']:
            prompt_parts.append(f"User: {query}")
            prompt_parts.append("")
            prompt_parts.append("Please respond naturally to the user's message.")
        else:
            prompt_parts.append("Network Traffic Analysis Context:")
            prompt_parts.append(context)
            prompt_parts.append("")
            prompt_parts.append(f"User Question: {query}")
            prompt_parts.append("")

            if query_classification:
                if query_classification['is_summary_request']:
                    prompt_parts.append("The user is asking for a summary. Provide a clear, concise overview of the key findings.")
                elif query_classification['is_threat_focused']:
                    prompt_parts.append("The user is asking about threats and security issues. Focus on VirusTotal results, suspicious IPs, domains, and potential security risks.")
                else:
                    prompt_parts.append("Answer the user's specific question based on the network traffic data. Be precise and cite relevant data points.")
            else:
                prompt_parts.append("Please provide a detailed answer based on the network traffic data provided. Focus on security implications, traffic patterns, and any anomalies.")

        return "\n".join(prompt_parts)

    def get_system_prompt(self) -> str:
        return """You are an interactive network security analyst assistant. You help users analyze network traffic data from PCAP files in a conversational and friendly manner.

Your capabilities:
- Respond naturally to greetings and casual conversation
- Provide summaries and overviews of network traffic analysis
- Answer specific questions about IPs, domains, protocols, and packets
- Identify threats, malicious activity, and suspicious patterns using VirusTotal results
- Explain security implications and provide recommendations
- Engage in back-and-forth conversation to clarify user needs

Conversational guidelines:
- When users greet you (hi, hello, etc.), respond warmly and introduce yourself briefly
- If users ask what you can do, explain your capabilities and offer to help
- When users ask for a summary, provide a clear overview of key findings
- For specific questions, provide precise answers based on the traffic data
- If information isn't in the provided context, politely say so and suggest related information you can provide
- Maintain conversation context and reference previous exchanges when relevant
- Be concise but informative - adjust detail level based on user's questions

Security analysis focus:
- Always highlight malicious or suspicious entities flagged by VirusTotal
- Explain protocol distributions and their implications
- Identify unusual patterns or anomalies in traffic
- Provide actionable security recommendations
- Cite specific data points (IPs, domains, packet counts) when making claims

Remember: You're having a conversation with a human analyst. Be helpful, interactive, and adaptive to their needs."""

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
