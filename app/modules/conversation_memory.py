from typing import Dict, List, Any, Optional
from datetime import datetime
import json


class ConversationMemory:
    """
    Manages short-term conversation memory for Option 3 agentic workflow.
    Tracks conversation history, discovered entities, and analysis results.
    """

    def __init__(self, max_history: int = 10):
        self.max_history = max_history
        self.conversation_history: List[Dict[str, Any]] = []
        self.discovered_entities: Dict[str, List[Any]] = {
            'ips': [],
            'domains': [],
            'ports': [],
            'protocols': [],
            'credentials': [],
            'file_transfers': [],
            'connections': []
        }
        self.analysis_cache: Dict[str, Any] = {}
        self.session_start = datetime.utcnow().isoformat()

    def add_exchange(
        self,
        user_query: str,
        llm_response: str,
        reasoning: Optional[str] = None,
        commands_executed: Optional[List[Dict[str, Any]]] = None,
        discovered_info: Optional[Dict[str, Any]] = None
    ):
        """Add a conversation exchange with all relevant context."""
        exchange = {
            'timestamp': datetime.utcnow().isoformat(),
            'user_query': user_query,
            'llm_response': llm_response,
            'reasoning': reasoning,
            'commands_executed': commands_executed or [],
            'discovered_info': discovered_info or {}
        }

        self.conversation_history.append(exchange)

        if len(self.conversation_history) > self.max_history:
            self.conversation_history.pop(0)

        if discovered_info:
            self._extract_and_store_entities(discovered_info)

    def _extract_and_store_entities(self, discovered_info: Dict[str, Any]):
        """Extract and store discovered entities from analysis results."""
        if 'ips' in discovered_info:
            for ip in discovered_info['ips']:
                if ip not in self.discovered_entities['ips']:
                    self.discovered_entities['ips'].append(ip)

        if 'domains' in discovered_info:
            for domain in discovered_info['domains']:
                if domain not in self.discovered_entities['domains']:
                    self.discovered_entities['domains'].append(domain)

        if 'ports' in discovered_info:
            for port in discovered_info['ports']:
                if port not in self.discovered_entities['ports']:
                    self.discovered_entities['ports'].append(port)

        if 'protocols' in discovered_info:
            for protocol in discovered_info['protocols']:
                if protocol not in self.discovered_entities['protocols']:
                    self.discovered_entities['protocols'].append(protocol)

        if 'credentials' in discovered_info:
            self.discovered_entities['credentials'].extend(discovered_info['credentials'])

        if 'file_transfers' in discovered_info:
            self.discovered_entities['file_transfers'].extend(discovered_info['file_transfers'])

        if 'connections' in discovered_info:
            self.discovered_entities['connections'].extend(discovered_info['connections'])

    def get_conversation_context(self, last_n: int = 5) -> str:
        """Format recent conversation history for LLM context injection."""
        if not self.conversation_history:
            return "No previous conversation history."

        recent_history = self.conversation_history[-last_n:]
        context_parts = ["=== CONVERSATION MEMORY ==="]
        context_parts.append(f"Session started: {self.session_start}")
        context_parts.append(f"Total exchanges: {len(self.conversation_history)}\n")

        for i, exchange in enumerate(recent_history, 1):
            context_parts.append(f"--- Exchange {i} (at {exchange['timestamp']}) ---")
            context_parts.append(f"USER ASKED: {exchange['user_query']}")
            context_parts.append(f"YOU RESPONDED: {exchange['llm_response'][:300]}...")

            if exchange.get('discovered_info'):
                context_parts.append(f"DISCOVERED: {json.dumps(exchange['discovered_info'], indent=2)}")

            context_parts.append("")

        return "\n".join(context_parts)

    def get_discovered_entities_context(self) -> str:
        """Format discovered entities for LLM context."""
        if not any(self.discovered_entities.values()):
            return "No entities discovered yet in this conversation."

        context_parts = ["=== DISCOVERED ENTITIES IN THIS SESSION ==="]

        if self.discovered_entities['ips']:
            context_parts.append(f"IPs found: {', '.join(self.discovered_entities['ips'][:20])}")

        if self.discovered_entities['domains']:
            context_parts.append(f"Domains found: {', '.join(self.discovered_entities['domains'][:20])}")

        if self.discovered_entities['protocols']:
            context_parts.append(f"Protocols: {', '.join(set(self.discovered_entities['protocols']))}")

        if self.discovered_entities['credentials']:
            context_parts.append(f"Credentials discovered: {len(self.discovered_entities['credentials'])} entries")
            for cred in self.discovered_entities['credentials'][-5:]:
                context_parts.append(f"  - {cred}")

        if self.discovered_entities['file_transfers']:
            context_parts.append(f"File transfers tracked: {len(self.discovered_entities['file_transfers'])}")

        if self.discovered_entities['connections']:
            context_parts.append(f"Connections analyzed: {len(self.discovered_entities['connections'])}")

        return "\n".join(context_parts)

    def cache_analysis_result(self, key: str, result: Any):
        """Cache analysis results to avoid re-executing commands."""
        self.analysis_cache[key] = {
            'result': result,
            'cached_at': datetime.utcnow().isoformat()
        }

    def get_cached_result(self, key: str) -> Optional[Any]:
        """Retrieve cached analysis result if available."""
        if key in self.analysis_cache:
            return self.analysis_cache[key]['result']
        return None

    def resolve_reference(self, query: str) -> Optional[str]:
        """
        Resolve contextual references in user queries like 'this ip', 'that domain', 'the password'.
        Returns enriched query with resolved references.
        """
        query_lower = query.lower()

        if any(ref in query_lower for ref in ['this ip', 'that ip', 'the ip']):
            if self.discovered_entities['ips']:
                most_recent_ip = self.discovered_entities['ips'][-1]
                return f"[Context: User is referring to IP {most_recent_ip}] {query}"

        if any(ref in query_lower for ref in ['this domain', 'that domain', 'the domain']):
            if self.discovered_entities['domains']:
                most_recent_domain = self.discovered_entities['domains'][-1]
                return f"[Context: User is referring to domain {most_recent_domain}] {query}"

        if any(ref in query_lower for ref in ['the password', 'that password', 'its password']):
            if self.conversation_history:
                last_exchange = self.conversation_history[-1]
                last_query = last_exchange['user_query']
                return f"[Context: User is asking about password related to previous query: '{last_query}'] {query}"

        if any(ref in query_lower for ref in ['this user', 'that user', 'the user']):
            if self.conversation_history:
                last_exchange = self.conversation_history[-1]
                last_query = last_exchange['user_query']
                return f"[Context: User is asking about a user mentioned in: '{last_query}'] {query}"

        return None

    def get_last_topic(self) -> Optional[str]:
        """Get the topic of the last conversation exchange."""
        if not self.conversation_history:
            return None

        last_exchange = self.conversation_history[-1]
        return last_exchange['user_query']

    def clear(self):
        """Clear all conversation memory."""
        self.conversation_history.clear()
        self.discovered_entities = {
            'ips': [],
            'domains': [],
            'ports': [],
            'protocols': [],
            'credentials': [],
            'file_transfers': [],
            'connections': []
        }
        self.analysis_cache.clear()
        self.session_start = datetime.utcnow().isoformat()
