"""
Enhanced summary generator that creates intelligent, context-rich PCAP summaries.
Produces compact but information-dense summaries optimized for LLM consumption.
"""

from typing import Dict, List, Any, Optional
from collections import Counter
from .entity_analyzer import EntityAnalyzer


class EnhancedSummaryGenerator:
    """Generates intelligent, compact summaries from PCAP data."""

    def __init__(self):
        self.analyzer = EntityAnalyzer()

    def generate_enhanced_summary(self,
                                  summary_data: Dict[str, Any],
                                  vt_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate an enhanced summary with intelligent prioritization and context."""

        # Build VT lookup for threat status
        vt_lookup = self._build_vt_lookup(vt_results)

        # Enrich and score entities
        enriched_ips = self._enrich_and_score_ips(summary_data, vt_lookup)
        enriched_domains = self._enrich_and_score_domains(summary_data, vt_lookup)
        enriched_flows = self._enrich_and_score_flows(summary_data, vt_lookup)

        # Create aggregate statistics
        entity_stats = self.analyzer.create_entity_statistics(enriched_ips, enriched_domains)

        # Analyze behaviors
        http_sessions = summary_data.get('http_sessions', [])
        dns_queries = summary_data.get('dns_queries', [])
        tcp_connections = summary_data.get('tcp_connections', [])

        http_behavior = self.analyzer.classify_http_behavior(http_sessions)
        dns_behavior = self.analyzer.classify_dns_behavior(dns_queries)
        behavioral_patterns = self.analyzer.identify_behavioral_patterns(enriched_ips, tcp_connections)
        enriched_tcp = self.analyzer.enrich_tcp_connections(tcp_connections)

        # Create IP-domain relationships
        ip_domain_map = self.analyzer.create_ip_domain_relationships(dns_queries, http_sessions)

        # Sort and select top entities
        top_ips = self._select_top_entities(enriched_ips, limit=50)
        top_domains = self._select_top_entities(enriched_domains, limit=50)
        top_flows = self._select_top_entities(enriched_flows, limit=20)

        # Group HTTP sessions by domain
        http_summary = self._create_http_session_summary(http_sessions, vt_lookup)

        # Create DNS resolution summary
        dns_summary = self._create_dns_summary(dns_queries, vt_lookup)

        # Select top TCP connections
        top_tcp = self._select_top_tcp_connections(enriched_tcp, limit=40)

        # Create threat narrative
        threat_narrative = self._create_threat_narrative(vt_results, enriched_ips, enriched_domains)

        # Build enhanced summary
        enhanced_summary = {
            'file_info': summary_data.get('file_info', {}),
            'statistics': {
                'total_packets': summary_data.get('statistics', {}).get('total_packets', 0),
                'top_protocols': summary_data.get('statistics', {}).get('top_protocols', {}),
                'unique_ips_count': entity_stats['total_ips'],
                'unique_domains_count': entity_stats['total_domains'],
                'threat_ips_count': entity_stats['threat_ips'],
                'threat_domains_count': entity_stats['threat_domains'],
            },
            'threat_summary': threat_narrative,
            'behavioral_patterns': behavioral_patterns,
            'top_entities': {
                'ips': top_ips,
                'domains': top_domains,
                'flows': top_flows
            },
            'http_activity': http_summary,
            'dns_activity': dns_summary,
            'tcp_connections': top_tcp,
            'ip_domain_relationships': ip_domain_map,
            'http_behavior_analysis': http_behavior,
            'dns_behavior_analysis': dns_behavior,
            'entity_statistics': entity_stats,
            'virustotal_results': self._compact_vt_results(vt_results)
        }

        return enhanced_summary

    def _build_vt_lookup(self, vt_results: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Build a lookup dictionary for VT results."""
        lookup = {}
        for result in vt_results:
            entity_value = result.get('entity_value')
            if entity_value:
                lookup[entity_value] = {
                    'entity_type': result.get('entity_type'),
                    'malicious_count': result.get('malicious_count', 0),
                    'suspicious_count': result.get('suspicious_count', 0),
                    'threat_label': result.get('threat_label'),
                    'reputation': result.get('reputation', 0)
                }
        return lookup

    def _enrich_and_score_ips(self,
                              summary_data: Dict[str, Any],
                              vt_lookup: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Enrich IP addresses with context and calculate relevance scores."""

        ip_data = {}
        unique_ips = summary_data.get('unique_entities', {}).get('ips', [])
        top_flows = summary_data.get('top_flows', {})
        http_sessions = summary_data.get('http_sessions', [])
        tcp_connections = summary_data.get('tcp_connections', [])

        for ip in unique_ips:
            enriched = {
                'ip': ip,
                'packet_count': 0,
                'total_bytes': 0,
                'bytes_sent': 0,
                'bytes_received': 0,
                'connection_count': 0,
                'protocols': set(),
                'has_http': False,
                'has_dns': False,
                'tcp_established': False,
                'unique_dst_ports': set(),
                'first_seen': None,
                'last_seen': None,
                'activity_duration_seconds': 0,
                'threat_status': 'clean'
            }

            # Check VT status
            if ip in vt_lookup:
                vt_info = vt_lookup[ip]
                if vt_info['malicious_count'] > 0:
                    enriched['threat_status'] = 'malicious'
                    enriched['threat_label'] = vt_info.get('threat_label', 'Unknown threat')
                    enriched['malicious_vendors'] = vt_info['malicious_count']
                elif vt_info['suspicious_count'] > 0:
                    enriched['threat_status'] = 'suspicious'
                    enriched['suspicious_vendors'] = vt_info['suspicious_count']

            # Aggregate flow data
            for flow_key, flow_metadata in top_flows.items():
                if ip in flow_key:
                    enriched['packet_count'] += flow_metadata.get('packet_count', 0)
                    enriched['total_bytes'] += flow_metadata.get('total_bytes', 0)
                    enriched['protocols'].add(flow_metadata.get('protocol', 'UNKNOWN'))

                    # Track first/last seen
                    first = flow_metadata.get('first_seen')
                    last = flow_metadata.get('last_seen')
                    if first and (not enriched['first_seen'] or first < enriched['first_seen']):
                        enriched['first_seen'] = first
                    if last and (not enriched['last_seen'] or last > enriched['last_seen']):
                        enriched['last_seen'] = last

            # HTTP activity
            for session in http_sessions:
                if session.get('src_ip') == ip or session.get('dst_ip') == ip:
                    enriched['has_http'] = True

            # TCP connections
            for conn in tcp_connections:
                if conn.get('src_ip') == ip or conn.get('dst_ip') == ip:
                    enriched['connection_count'] += 1
                    if conn.get('state') == 'ESTABLISHED':
                        enriched['tcp_established'] = True

                    # Track destination ports for scanning detection
                    if conn.get('src_ip') == ip:
                        dst_port = conn.get('dst_port')
                        if dst_port:
                            enriched['unique_dst_ports'].add(str(dst_port))

            # Convert sets to lists for JSON
            enriched['protocols'] = list(enriched['protocols'])
            enriched['unique_dst_ports'] = list(enriched['unique_dst_ports'])

            # Calculate relevance score
            enriched['relevance_score'] = self.analyzer.score_ip_relevance(enriched)

            ip_data[ip] = enriched

        return ip_data

    def _enrich_and_score_domains(self,
                                  summary_data: Dict[str, Any],
                                  vt_lookup: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Enrich domains with context and calculate relevance scores."""

        domain_data = {}
        unique_domains = summary_data.get('unique_entities', {}).get('domains', [])
        http_sessions = summary_data.get('http_sessions', [])
        dns_queries = summary_data.get('dns_queries', [])

        for domain in unique_domains:
            enriched = {
                'domain': domain,
                'request_count': 0,
                'total_bytes': 0,
                'accessed_via_http': False,
                'accessed_via_dns': False,
                'failed_resolutions': 0,
                'resolved_ips': set(),
                'threat_status': 'clean'
            }

            # Check VT status
            if domain in vt_lookup:
                vt_info = vt_lookup[domain]
                if vt_info['malicious_count'] > 0:
                    enriched['threat_status'] = 'malicious'
                    enriched['threat_label'] = vt_info.get('threat_label', 'Unknown threat')
                    enriched['malicious_vendors'] = vt_info['malicious_count']
                elif vt_info['suspicious_count'] > 0:
                    enriched['threat_status'] = 'suspicious'
                    enriched['suspicious_vendors'] = vt_info['suspicious_count']

            # HTTP data
            for session in http_sessions:
                if session.get('host') == domain:
                    enriched['request_count'] += 1
                    enriched['accessed_via_http'] = True
                    content_length = session.get('content_length', 0)
                    if content_length:
                        try:
                            enriched['total_bytes'] += int(content_length)
                        except:
                            pass

            # DNS data
            for query in dns_queries:
                if query.get('query_name') == domain:
                    enriched['request_count'] += 1
                    enriched['accessed_via_dns'] = True

                    resolved_ip = query.get('resolved_ip')
                    if resolved_ip:
                        enriched['resolved_ips'].add(resolved_ip)
                    elif query.get('is_response'):
                        enriched['failed_resolutions'] += 1

            # Convert sets to lists
            enriched['resolved_ips'] = list(enriched['resolved_ips'])

            # Calculate relevance score
            enriched['relevance_score'] = self.analyzer.score_domain_relevance(enriched)

            domain_data[domain] = enriched

        return domain_data

    def _enrich_and_score_flows(self,
                                summary_data: Dict[str, Any],
                                vt_lookup: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Enrich network flows with context and calculate relevance scores."""

        flow_data = {}
        top_flows = summary_data.get('top_flows', {})

        for flow_key, flow_metadata in top_flows.items():
            # Parse flow key
            parts = flow_key.split('->')
            if len(parts) == 2:
                src_part = parts[0]
                dst_part = parts[1]

                enriched = {
                    'flow_key': flow_key,
                    'src': src_part,
                    'dst': dst_part,
                    'packet_count': flow_metadata.get('packet_count', 0),
                    'total_bytes': flow_metadata.get('total_bytes', 0),
                    'protocol': flow_metadata.get('protocol', 'UNKNOWN'),
                    'first_seen': flow_metadata.get('first_seen'),
                    'last_seen': flow_metadata.get('last_seen'),
                    'involves_threat': False
                }

                # Check if flow involves any threats
                src_ip = src_part.split(':')[0] if ':' in src_part else src_part
                dst_ip = dst_part.split(':')[0] if ':' in dst_part else dst_part

                if src_ip in vt_lookup or dst_ip in vt_lookup:
                    enriched['involves_threat'] = True

                # Calculate relevance score
                enriched['relevance_score'] = self.analyzer.score_flow_relevance(enriched)

                flow_data[flow_key] = enriched

        return flow_data

    def _select_top_entities(self,
                            entity_dict: Dict[str, Dict[str, Any]],
                            limit: int) -> List[Dict[str, Any]]:
        """Select top entities by relevance score, prioritizing threats."""

        # Separate threats and clean entities
        threats = [data for data in entity_dict.values()
                  if data.get('threat_status') in ['malicious', 'suspicious']]
        clean = [data for data in entity_dict.values()
                if data.get('threat_status') == 'clean']

        # Sort both by relevance score
        threats.sort(key=lambda x: x.get('relevance_score', 0), reverse=True)
        clean.sort(key=lambda x: x.get('relevance_score', 0), reverse=True)

        # Always include ALL threats, then fill remaining slots with top clean entities
        result = threats
        remaining_slots = limit - len(threats)
        if remaining_slots > 0:
            result.extend(clean[:remaining_slots])

        return result

    def _create_http_session_summary(self,
                                    http_sessions: List[Dict[str, Any]],
                                    vt_lookup: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Create a grouped summary of HTTP sessions by domain."""

        domain_groups = {}

        for session in http_sessions:
            host = session.get('host', 'unknown')

            if host not in domain_groups:
                domain_groups[host] = {
                    'domain': host,
                    'request_count': 0,
                    'methods': Counter(),
                    'status_codes': Counter(),
                    'total_bytes': 0,
                    'sample_requests': [],
                    'threat_status': 'clean'
                }

            group = domain_groups[host]
            group['request_count'] += 1

            method = session.get('method', 'GET')
            group['methods'][method] += 1

            status = session.get('status_code')
            if status:
                group['status_codes'][status] += 1

            content_length = session.get('content_length', 0)
            if content_length:
                try:
                    group['total_bytes'] += int(content_length)
                except:
                    pass

            # Store sample requests (max 3 per domain)
            if len(group['sample_requests']) < 3:
                sample = {
                    'method': method,
                    'uri': session.get('uri', '/'),
                    'status_code': status
                }
                group['sample_requests'].append(sample)

            # Check threat status
            if host in vt_lookup:
                vt_info = vt_lookup[host]
                if vt_info['malicious_count'] > 0:
                    group['threat_status'] = 'malicious'
                    group['malicious_vendors'] = vt_info['malicious_count']
                elif vt_info['suspicious_count'] > 0:
                    group['threat_status'] = 'suspicious'

        # Convert Counters to dicts and sort by request count
        for group in domain_groups.values():
            group['methods'] = dict(group['methods'])
            group['status_codes'] = dict(group['status_codes'])

        # Sort by threat status then request count
        sorted_groups = sorted(domain_groups.values(),
                              key=lambda x: (x['threat_status'] != 'malicious',
                                           x['threat_status'] != 'suspicious',
                                           -x['request_count']))

        return {
            'total_sessions': len(http_sessions),
            'unique_domains': len(domain_groups),
            'domain_groups': sorted_groups[:30]  # Top 30 domain groups
        }

    def _create_dns_summary(self,
                           dns_queries: List[Dict[str, Any]],
                           vt_lookup: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Create a grouped summary of DNS queries."""

        domain_resolutions = {}

        for query in dns_queries:
            domain = query.get('query_name')
            if not domain:
                continue

            if domain not in domain_resolutions:
                domain_resolutions[domain] = {
                    'domain': domain,
                    'query_count': 0,
                    'resolved_ips': set(),
                    'query_types': Counter(),
                    'failed_count': 0,
                    'threat_status': 'clean'
                }

            res = domain_resolutions[domain]
            res['query_count'] += 1

            query_type = query.get('query_type', 'A')
            res['query_types'][query_type] += 1

            resolved_ip = query.get('resolved_ip')
            if resolved_ip:
                res['resolved_ips'].add(resolved_ip)
            elif query.get('is_response'):
                res['failed_count'] += 1

            # Check threat status
            if domain in vt_lookup:
                vt_info = vt_lookup[domain]
                if vt_info['malicious_count'] > 0:
                    res['threat_status'] = 'malicious'
                    res['malicious_vendors'] = vt_info['malicious_count']

        # Convert sets and Counters to lists/dicts
        for res in domain_resolutions.values():
            res['resolved_ips'] = list(res['resolved_ips'])
            res['query_types'] = dict(res['query_types'])

        # Sort by threat status then query count
        sorted_resolutions = sorted(domain_resolutions.values(),
                                   key=lambda x: (x['threat_status'] != 'malicious',
                                                x['threat_status'] != 'suspicious',
                                                -x['query_count']))

        return {
            'total_queries': len(dns_queries),
            'unique_domains': len(domain_resolutions),
            'resolutions': sorted_resolutions[:30]  # Top 30 domains
        }

    def _select_top_tcp_connections(self,
                                    enriched_tcp: List[Dict[str, Any]],
                                    limit: int) -> List[Dict[str, Any]]:
        """Select most relevant TCP connections."""

        # Priority: established > incomplete > terminated
        priority_map = {'complete': 3, 'incomplete': 2, 'terminated': 1, 'unknown': 0}

        sorted_tcp = sorted(enriched_tcp,
                           key=lambda x: (priority_map.get(x.get('quality', 'unknown'), 0),
                                        x.get('service', 'Dynamic') in ['HTTP', 'HTTPS', 'DNS']),
                           reverse=True)

        return sorted_tcp[:limit]

    def _create_threat_narrative(self,
                                 vt_results: List[Dict[str, Any]],
                                 enriched_ips: Dict[str, Dict[str, Any]],
                                 enriched_domains: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Create a narrative summary of threats found."""

        threats = [r for r in vt_results if r.get('malicious_count', 0) > 0]
        suspicious = [r for r in vt_results if r.get('suspicious_count', 0) > 0 and r.get('malicious_count', 0) == 0]

        threat_narrative = {
            'severity': 'CLEAN',
            'summary': 'No threats detected',
            'threat_count': len(threats),
            'suspicious_count': len(suspicious),
            'threats': [],
            'recommendations': []
        }

        if threats:
            # Determine severity
            critical_threats = [t for t in threats if t.get('malicious_count', 0) >= 10]
            if critical_threats:
                threat_narrative['severity'] = 'CRITICAL'
            elif len(threats) >= 3:
                threat_narrative['severity'] = 'HIGH'
            else:
                threat_narrative['severity'] = 'MEDIUM'

            # Create summary
            threat_types = Counter([t.get('entity_type') for t in threats])
            threat_narrative['summary'] = f"{len(threats)} malicious entities detected: "
            threat_narrative['summary'] += ", ".join([f"{count} {etype}(s)" for etype, count in threat_types.items()])

            # Detail each threat
            for threat in threats[:10]:  # Top 10 threats
                entity_type = threat.get('entity_type', 'unknown')
                entity_value = threat.get('entity_value')
                malicious_count = threat.get('malicious_count', 0)
                threat_label = threat.get('threat_label', 'Unknown threat')

                threat_detail = {
                    'type': entity_type,
                    'value': entity_value,
                    'severity': 'critical' if malicious_count >= 10 else 'high' if malicious_count >= 5 else 'medium',
                    'malicious_vendors': malicious_count,
                    'threat_label': threat_label,
                    'detection_engines': threat.get('detection_engines', [])[:3]  # Top 3 only
                }

                # Add context from enriched data
                if entity_type == 'ip' and entity_value in enriched_ips:
                    ip_data = enriched_ips[entity_value]
                    threat_detail['packet_count'] = ip_data.get('packet_count', 0)
                    threat_detail['protocols'] = ip_data.get('protocols', [])
                elif entity_type == 'domain' and entity_value in enriched_domains:
                    domain_data = enriched_domains[entity_value]
                    threat_detail['request_count'] = domain_data.get('request_count', 0)
                    threat_detail['resolved_ips'] = domain_data.get('resolved_ips', [])

                threat_narrative['threats'].append(threat_detail)

            # Generate recommendations
            if any(t.get('entity_type') == 'ip' for t in threats):
                threat_narrative['recommendations'].append("Block malicious IP addresses at firewall level")
            if any(t.get('entity_type') == 'domain' for t in threats):
                threat_narrative['recommendations'].append("Add malicious domains to DNS blocklist")
            if any(t.get('entity_type') == 'file' for t in threats):
                threat_narrative['recommendations'].append("Quarantine and analyze malicious files immediately")

        return threat_narrative

    def _compact_vt_results(self, vt_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create a compact version of VT results for storage."""

        compact = {
            'total_queried': len(vt_results),
            'malicious': [],
            'suspicious': [],
            'clean_count': 0
        }

        for result in vt_results:
            malicious_count = result.get('malicious_count', 0)
            suspicious_count = result.get('suspicious_count', 0)

            if malicious_count > 0:
                compact['malicious'].append({
                    'entity_type': result.get('entity_type'),
                    'entity_value': result.get('entity_value'),
                    'malicious_count': malicious_count,
                    'threat_label': result.get('threat_label'),
                    'top_detections': result.get('detection_engines', [])[:3]
                })
            elif suspicious_count > 0:
                compact['suspicious'].append({
                    'entity_type': result.get('entity_type'),
                    'entity_value': result.get('entity_value'),
                    'suspicious_count': suspicious_count
                })
            else:
                compact['clean_count'] += 1

        return compact
