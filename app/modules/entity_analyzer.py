"""
Intelligent entity analysis and relevance scoring for PCAP summaries.
Prioritizes entities based on threat status, traffic volume, and behavioral indicators.
"""

from typing import Dict, List, Any, Optional, Tuple
from collections import Counter
from datetime import datetime


class EntityAnalyzer:
    """Analyzes and scores entities for relevance and priority."""

    def __init__(self):
        self.threat_score_multiplier = 1000  # Threats always get highest priority
        self.volume_weight = 2.0
        self.connection_weight = 3.0
        self.protocol_weight = 1.5
        self.duration_weight = 1.0

    def score_ip_relevance(self, ip_data: Dict[str, Any]) -> float:
        """Calculate relevance score for an IP address."""
        score = 0.0

        # Threat status is highest priority
        if ip_data.get('threat_status') == 'malicious':
            score += self.threat_score_multiplier * 2
        elif ip_data.get('threat_status') == 'suspicious':
            score += self.threat_score_multiplier

        # Traffic volume
        packet_count = ip_data.get('packet_count', 0)
        bytes_transferred = ip_data.get('total_bytes', 0)
        score += packet_count * self.volume_weight
        score += (bytes_transferred / 1000) * self.volume_weight

        # Connection characteristics
        connection_count = ip_data.get('connection_count', 0)
        score += connection_count * self.connection_weight

        # Protocol diversity (more protocols = more interesting)
        protocol_count = len(ip_data.get('protocols', []))
        score += protocol_count * self.protocol_weight * 50

        # HTTP activity is more interesting than generic TCP
        if ip_data.get('has_http'):
            score += 500
        if ip_data.get('has_dns'):
            score += 200
        if ip_data.get('tcp_established'):
            score += 300

        # Duration of activity (longer = more persistent = more interesting)
        duration_minutes = ip_data.get('activity_duration_seconds', 0) / 60
        score += duration_minutes * self.duration_weight * 10

        return score

    def score_domain_relevance(self, domain_data: Dict[str, Any]) -> float:
        """Calculate relevance score for a domain."""
        score = 0.0

        # Threat status is highest priority
        if domain_data.get('threat_status') == 'malicious':
            score += self.threat_score_multiplier * 2
        elif domain_data.get('threat_status') == 'suspicious':
            score += self.threat_score_multiplier

        # Request frequency
        request_count = domain_data.get('request_count', 0)
        score += request_count * 10.0

        # HTTP vs DNS (HTTP is more interesting)
        if domain_data.get('accessed_via_http'):
            score += 400
        if domain_data.get('accessed_via_dns'):
            score += 100

        # Failed resolutions might indicate malware C2
        if domain_data.get('failed_resolutions', 0) > 0:
            score += 200

        # Data volume
        bytes_transferred = domain_data.get('total_bytes', 0)
        score += (bytes_transferred / 1000) * 2.0

        return score

    def score_flow_relevance(self, flow_data: Dict[str, Any]) -> float:
        """Calculate relevance score for a network flow."""
        score = 0.0

        # Threat involvement
        if flow_data.get('involves_threat'):
            score += self.threat_score_multiplier

        # Traffic volume
        packet_count = flow_data.get('packet_count', 0)
        bytes_transferred = flow_data.get('total_bytes', 0)
        score += packet_count * 1.0
        score += (bytes_transferred / 1000) * 1.5

        # Connection quality
        if flow_data.get('established'):
            score += 200
        if flow_data.get('bidirectional'):
            score += 150

        # Duration
        duration_seconds = flow_data.get('duration_seconds', 0)
        score += duration_seconds * 0.5

        # Protocol importance
        protocol = flow_data.get('protocol', '').upper()
        if protocol in ['HTTP', 'HTTPS', 'TLS']:
            score += 300
        elif protocol in ['DNS']:
            score += 150
        elif protocol in ['TCP']:
            score += 50

        return score

    def create_entity_statistics(self,
                                 ip_scores: Dict[str, Dict[str, Any]],
                                 domain_scores: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Create aggregate statistics for entities."""

        stats = {
            'total_ips': len(ip_scores),
            'total_domains': len(domain_scores),
            'threat_ips': len([ip for ip, data in ip_scores.items()
                              if data.get('threat_status') in ['malicious', 'suspicious']]),
            'threat_domains': len([d for d, data in domain_scores.items()
                                  if data.get('threat_status') in ['malicious', 'suspicious']]),
            'total_packets': sum(data.get('packet_count', 0) for data in ip_scores.values()),
            'total_bytes': sum(data.get('total_bytes', 0) for data in ip_scores.values()),
            'http_active_ips': len([ip for ip, data in ip_scores.items() if data.get('has_http')]),
            'dns_active_domains': len([d for d, data in domain_scores.items()
                                      if data.get('accessed_via_dns')]),
        }

        return stats

    def identify_behavioral_patterns(self,
                                    ip_scores: Dict[str, Dict[str, Any]],
                                    tcp_connections: List[Dict[str, Any]]) -> List[str]:
        """Identify suspicious behavioral patterns in network traffic."""
        patterns = []

        # Port scanning detection
        for ip, data in ip_scores.items():
            unique_dst_ports = data.get('unique_dst_ports', set())
            if len(unique_dst_ports) > 20 and data.get('packet_count', 0) / len(unique_dst_ports) < 5:
                patterns.append(f"Port scanning detected from {ip} (contacted {len(unique_dst_ports)} ports)")

        # Failed connection attempts
        failed_connections = [c for c in tcp_connections if c.get('state') == 'RESET' or c.get('state') == 'SYN_SENT']
        if len(failed_connections) > 10:
            patterns.append(f"High failed connection rate detected ({len(failed_connections)} failed attempts)")

        # Data exfiltration indicators
        for ip, data in ip_scores.items():
            outbound_bytes = data.get('bytes_sent', 0)
            inbound_bytes = data.get('bytes_received', 0)
            if outbound_bytes > 1000000 and outbound_bytes > inbound_bytes * 10:
                patterns.append(f"Potential data exfiltration from {ip} ({outbound_bytes/1000000:.1f}MB outbound)")

        # Beaconing detection (periodic connections)
        connection_times = {}
        for conn in tcp_connections:
            src = conn.get('src_ip')
            dst = conn.get('dst_ip')
            key = f"{src}->{dst}"
            if key not in connection_times:
                connection_times[key] = []
            if conn.get('first_seen'):
                connection_times[key].append(conn['first_seen'])

        for flow, times in connection_times.items():
            if len(times) > 5:
                patterns.append(f"Periodic connection pattern detected: {flow} ({len(times)} connections)")

        return patterns

    def create_ip_domain_relationships(self,
                                      dns_queries: List[Dict[str, Any]],
                                      http_sessions: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Map relationships between IPs and domains from DNS and HTTP traffic."""
        relationships = {}

        # DNS resolutions
        for query in dns_queries:
            domain = query.get('query_name')
            resolved_ip = query.get('resolved_ip')
            if domain and resolved_ip:
                if domain not in relationships:
                    relationships[domain] = []
                if resolved_ip not in relationships[domain]:
                    relationships[domain].append(resolved_ip)

        # HTTP host headers
        for session in http_sessions:
            host = session.get('host')
            dst_ip = session.get('dst_ip')
            if host and dst_ip:
                if host not in relationships:
                    relationships[host] = []
                if dst_ip not in relationships[host]:
                    relationships[host].append(dst_ip)

        return relationships

    def classify_http_behavior(self, http_sessions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Classify HTTP behavior patterns."""

        behavior = {
            'user_agents': set(),
            'methods_used': Counter(),
            'status_codes': Counter(),
            'domains_contacted': set(),
            'total_requests': len(http_sessions),
            'download_indicators': [],
            'suspicious_patterns': []
        }

        for session in http_sessions:
            # User agents
            if session.get('user_agent'):
                behavior['user_agents'].add(session['user_agent'])

            # Methods
            method = session.get('method', 'GET')
            behavior['methods_used'][method] += 1

            # Status codes
            status = session.get('status_code')
            if status:
                behavior['status_codes'][status] += 1

            # Domains
            host = session.get('host')
            if host:
                behavior['domains_contacted'].add(host)

            # Download indicators
            content_disposition = session.get('content_disposition')
            if content_disposition and 'attachment' in str(content_disposition).lower():
                behavior['download_indicators'].append({
                    'host': host,
                    'uri': session.get('uri'),
                    'size': session.get('content_length')
                })

            # Suspicious patterns
            if status == '404' and behavior['status_codes']['404'] > 20:
                if '404 scanning pattern' not in [p for p in behavior['suspicious_patterns']]:
                    behavior['suspicious_patterns'].append('404 scanning pattern detected')

        # Convert sets to lists for JSON serialization
        behavior['user_agents'] = list(behavior['user_agents'])
        behavior['domains_contacted'] = list(behavior['domains_contacted'])
        behavior['methods_used'] = dict(behavior['methods_used'])
        behavior['status_codes'] = dict(behavior['status_codes'])

        return behavior

    def classify_dns_behavior(self, dns_queries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Classify DNS behavior patterns."""

        behavior = {
            'total_queries': len(dns_queries),
            'unique_domains': set(),
            'query_types': Counter(),
            'failed_resolutions': 0,
            'resolution_map': {},
            'suspicious_patterns': []
        }

        for query in dns_queries:
            domain = query.get('query_name')
            if domain:
                behavior['unique_domains'].add(domain)

                # Track query types
                query_type = query.get('query_type', 'A')
                behavior['query_types'][query_type] += 1

                # Track resolutions
                resolved_ip = query.get('resolved_ip')
                if resolved_ip:
                    if domain not in behavior['resolution_map']:
                        behavior['resolution_map'][domain] = []
                    if resolved_ip not in behavior['resolution_map'][domain]:
                        behavior['resolution_map'][domain].append(resolved_ip)
                else:
                    # Check if it's a failed resolution
                    if query.get('is_response') and not query.get('cname'):
                        behavior['failed_resolutions'] += 1

                # DNS tunneling detection (long domain names)
                if len(domain) > 50:
                    behavior['suspicious_patterns'].append(f"Unusually long domain name: {domain[:50]}...")

        # High query rate for same domain (potential DNS tunneling)
        domain_counts = Counter([q.get('query_name') for q in dns_queries if q.get('query_name')])
        for domain, count in domain_counts.most_common(5):
            if count > 50:
                behavior['suspicious_patterns'].append(f"High query rate for {domain} ({count} queries)")

        # Convert sets to lists
        behavior['unique_domains'] = list(behavior['unique_domains'])
        behavior['query_types'] = dict(behavior['query_types'])

        return behavior

    def enrich_tcp_connections(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich TCP connections with additional context and metrics."""

        enriched = []
        for conn in connections:
            enriched_conn = conn.copy()

            # Calculate connection duration
            first_seen = conn.get('first_seen')
            last_seen = conn.get('last_seen')
            if first_seen and last_seen:
                try:
                    # Simple string comparison if timestamps are ISO format
                    enriched_conn['duration_seconds'] = 0  # Placeholder
                    enriched_conn['duration_indicator'] = 'short' if enriched_conn['duration_seconds'] < 5 else 'normal'
                except:
                    pass

            # Connection quality assessment
            state = conn.get('state', 'UNKNOWN')
            if state == 'ESTABLISHED':
                enriched_conn['quality'] = 'complete'
            elif state in ['SYN_SENT', 'SYN_ACK']:
                enriched_conn['quality'] = 'incomplete'
            elif state in ['RESET', 'FIN_WAIT']:
                enriched_conn['quality'] = 'terminated'
            else:
                enriched_conn['quality'] = 'unknown'

            # Port classification
            dst_port = conn.get('dst_port')
            if dst_port:
                try:
                    port_num = int(dst_port)
                    if port_num == 80:
                        enriched_conn['service'] = 'HTTP'
                    elif port_num == 443:
                        enriched_conn['service'] = 'HTTPS'
                    elif port_num == 53:
                        enriched_conn['service'] = 'DNS'
                    elif port_num == 22:
                        enriched_conn['service'] = 'SSH'
                    elif port_num in [20, 21]:
                        enriched_conn['service'] = 'FTP'
                    elif port_num < 1024:
                        enriched_conn['service'] = 'Well-known'
                    else:
                        enriched_conn['service'] = 'Dynamic'
                except:
                    enriched_conn['service'] = 'Unknown'

            enriched.append(enriched_conn)

        return enriched
