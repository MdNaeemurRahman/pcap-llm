from typing import Dict, Any


class QueryClassifier:
    def __init__(self):
        self.greeting_keywords = ['hi', 'hello', 'hey', 'greetings', 'good morning', 'good afternoon', 'good evening']
        self.help_keywords = ['help', 'what can you do', 'how to use', 'guide', 'instructions', 'capabilities']
        self.summary_keywords = ['summary', 'overview', 'summarize', 'brief', 'tell me about', 'what is this', 'explain this']
        self.threat_keywords = ['malicious', 'threat', 'attack', 'suspicious', 'dangerous', 'malware', 'virus', 'exploit', 'vulnerability']
        self.ip_keywords = ['ip', 'address', 'source', 'destination', 'host']
        self.domain_keywords = ['domain', 'dns', 'hostname', 'website', 'url']
        self.protocol_keywords = ['protocol', 'tcp', 'udp', 'http', 'https', 'icmp', 'dns query']
        self.packet_keywords = ['packet', 'packets', 'traffic', 'flow', 'communication', 'connection']

    def classify_query(self, query: str) -> Dict[str, Any]:
        query_lower = query.lower().strip()

        classification = {
            'type': 'specific',
            'intent': 'analyze',
            'requires_context': True,
            'is_greeting': False,
            'is_help_request': False,
            'is_summary_request': False,
            'is_threat_focused': False,
            'topics': []
        }

        if self._is_greeting(query_lower):
            classification['type'] = 'greeting'
            classification['intent'] = 'greet'
            classification['requires_context'] = False
            classification['is_greeting'] = True
            return classification

        if self._is_help_request(query_lower):
            classification['type'] = 'help'
            classification['intent'] = 'assist'
            classification['requires_context'] = False
            classification['is_help_request'] = True
            return classification

        if self._is_summary_request(query_lower):
            classification['type'] = 'summary'
            classification['intent'] = 'summarize'
            classification['is_summary_request'] = True

        if self._contains_threat_keywords(query_lower):
            classification['is_threat_focused'] = True
            classification['topics'].append('threat_analysis')

        classification['topics'].extend(self._identify_topics(query_lower))

        return classification

    def _is_greeting(self, query: str) -> bool:
        return any(greeting in query for greeting in self.greeting_keywords)

    def _is_help_request(self, query: str) -> bool:
        return any(keyword in query for keyword in self.help_keywords)

    def _is_summary_request(self, query: str) -> bool:
        return any(keyword in query for keyword in self.summary_keywords)

    def _contains_threat_keywords(self, query: str) -> bool:
        return any(keyword in query for keyword in self.threat_keywords)

    def _identify_topics(self, query: str) -> list:
        topics = []

        if any(keyword in query for keyword in self.ip_keywords):
            topics.append('ip_analysis')

        if any(keyword in query for keyword in self.domain_keywords):
            topics.append('domain_analysis')

        if any(keyword in query for keyword in self.protocol_keywords):
            topics.append('protocol_analysis')

        if any(keyword in query for keyword in self.packet_keywords):
            topics.append('packet_analysis')

        return topics

    def get_context_priority(self, classification: Dict[str, Any]) -> Dict[str, int]:
        priority = {
            'virustotal_results': 1 if classification['is_threat_focused'] else 3,
            'statistics': 1 if classification['is_summary_request'] else 2,
            'network_flows': 2,
            'http_sessions': 2 if 'protocol_analysis' in classification['topics'] else 3,
            'dns_queries': 2 if 'domain_analysis' in classification['topics'] else 3
        }

        return priority
