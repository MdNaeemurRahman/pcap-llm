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
            response = requests.post(url, json=payload, timeout=30)
            if response.status_code == 200:
                result = response.json()
                return result.get('embedding', [])
            else:
                print(f"Embedding generation failed: {response.status_code}")
                return None
        except Exception as e:
            print(f"Error generating embeddings: {str(e)}")
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
            response = requests.post(url, json=payload, timeout=120)

            if response.status_code == 200:
                if stream:
                    full_response = ""
                    for line in response.iter_lines():
                        if line:
                            chunk_data = json.loads(line)
                            if 'response' in chunk_data:
                                full_response += chunk_data['response']
                            if chunk_data.get('done', False):
                                break
                    return full_response
                else:
                    result = response.json()
                    return result.get('response', '')
            else:
                return f"Error: LLM generation failed with status {response.status_code}"
        except Exception as e:
            return f"Error generating LLM response: {str(e)}"

    def format_prompt_for_network_analysis(self, query: str, context: str, chat_history: Optional[List[Dict[str, str]]] = None) -> str:
        prompt_parts = []

        if chat_history:
            prompt_parts.append("Previous conversation:")
            for msg in chat_history[-5:]:
                prompt_parts.append(f"User: {msg['user']}")
                prompt_parts.append(f"Assistant: {msg['assistant']}")
            prompt_parts.append("")

        prompt_parts.append("Network Traffic Analysis Context:")
        prompt_parts.append(context)
        prompt_parts.append("")
        prompt_parts.append(f"User Question: {query}")
        prompt_parts.append("")
        prompt_parts.append("Please provide a detailed answer based on the network traffic data provided. Focus on security implications, traffic patterns, and any anomalies.")

        return "\n".join(prompt_parts)

    def get_system_prompt(self) -> str:
        return """You are a network security analyst assistant. Your task is to analyze network traffic data from PCAP files and help users understand security implications, traffic patterns, and potential threats.

When analyzing network traffic:
- Identify suspicious IPs or domains based on VirusTotal results
- Explain protocol distributions and what they indicate
- Highlight unusual traffic patterns or behaviors
- Provide security recommendations when relevant
- Be clear and concise in your responses

Always base your answers on the provided network traffic data."""

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
