import json
from typing import Dict, List, Any, Optional


class TextChunker:
    def __init__(self, max_chunk_size: int = 100):
        self.max_chunk_size = max_chunk_size

    def _normalize_vt_results(self, vt_results: Any) -> Dict[str, Any]:
        """Normalize VT results to dictionary format with 'results' key."""
        if isinstance(vt_results, dict) and 'results' in vt_results:
            return vt_results

        if isinstance(vt_results, list):
            normalized = {
                'results': {
                    'ip': {},
                    'domain': {},
                    'file': {}
                }
            }

            for item in vt_results:
                if not isinstance(item, dict):
                    continue

                entity_type = item.get('entity_type')
                entity_value = item.get('entity_value')

                if not entity_type or not entity_value:
                    continue

                entity_data = {
                    'malicious': item.get('malicious_count', 0),
                    'suspicious': item.get('suspicious_count', 0),
                    'harmless': item.get('harmless_count', 0),
                    'undetected': item.get('undetected_count', 0),
                    'threat_label': item.get('threat_label', 'Unknown'),
                    'categories': []
                }

                if entity_type == 'domain' and item.get('category'):
                    entity_data['categories'] = list(item['category'].values()) if isinstance(item['category'], dict) else []

                if entity_type == 'file':
                    entity_data['detection_engines'] = item.get('detection_engines', [])
                    entity_data['threat_category'] = item.get('threat_category', [])
                    entity_data['sandbox_verdicts'] = item.get('sandbox_verdicts', [])

                if entity_type in normalized['results']:
                    normalized['results'][entity_type][entity_value] = entity_data

            return normalized

        return {}

    def chunk_by_packet_range(self, full_json_data: Dict[str, Any], vt_results: Optional[Any] = None) -> List[Dict[str, Any]]:
        packets = full_json_data.get('packets', [])
        if not packets:
            return []

        chunks = []
        chunk_index = 0

        # Create forensic metadata chunk FIRST (Chunk 0) for priority retrieval
        if full_json_data.get('forensic_analysis'):
            forensic_chunk = self._create_forensic_metadata_chunk(
                full_json_data['forensic_analysis'],
                chunk_index
            )
            chunks.append(forensic_chunk)
            chunk_index += 1

        normalized_vt_results = self._normalize_vt_results(vt_results) if vt_results else {}
        vt_lookup = self._build_vt_lookup(normalized_vt_results) if normalized_vt_results else {}

        for i in range(0, len(packets), self.max_chunk_size):
            chunk_packets = packets[i:i + self.max_chunk_size]
            chunk = self._create_chunk(chunk_packets, chunk_index, i, min(i + self.max_chunk_size, len(packets)), vt_lookup)
            chunks.append(chunk)
            chunk_index += 1

        if normalized_vt_results and normalized_vt_results.get('results'):
            threat_chunks = self._create_threat_intelligence_chunks(normalized_vt_results, chunk_index)
            chunks.extend(threat_chunks)

        return chunks

    def _build_vt_lookup(self, vt_results: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        lookup = {}

        if not vt_results or 'results' not in vt_results:
            return lookup

        for entity_type, entities in vt_results['results'].items():
            for entity_value, entity_data in entities.items():
                if entity_data and entity_data.get('malicious', 0) > 0:
                    lookup[entity_value] = {
                        'type': entity_type,
                        'malicious_count': entity_data.get('malicious', 0),
                        'suspicious_count': entity_data.get('suspicious', 0),
                        'threat_label': entity_data.get('threat_label', 'Unknown'),
                        'categories': entity_data.get('categories', [])
                    }

        return lookup

    def _create_chunk(self, packets: List[Dict[str, Any]], chunk_index: int, start_idx: int, end_idx: int, vt_lookup: Dict[str, Dict[str, Any]] = None) -> Dict[str, Any]:
        if vt_lookup is None:
            vt_lookup = {}

        ips = set()
        domains = set()
        protocols = set()
        timestamps = []
        threats_in_chunk = []

        for packet in packets:
            if 'ip' in packet:
                src_ip = packet['ip']['src']
                dst_ip = packet['ip']['dst']
                ips.add(src_ip)
                ips.add(dst_ip)

                if src_ip in vt_lookup and src_ip not in [t['entity'] for t in threats_in_chunk]:
                    threats_in_chunk.append({'entity': src_ip, 'info': vt_lookup[src_ip]})
                if dst_ip in vt_lookup and dst_ip not in [t['entity'] for t in threats_in_chunk]:
                    threats_in_chunk.append({'entity': dst_ip, 'info': vt_lookup[dst_ip]})

            if 'ipv6' in packet:
                src_ip6 = packet['ipv6']['src']
                dst_ip6 = packet['ipv6']['dst']
                ips.add(src_ip6)
                ips.add(dst_ip6)

                if src_ip6 in vt_lookup and src_ip6 not in [t['entity'] for t in threats_in_chunk]:
                    threats_in_chunk.append({'entity': src_ip6, 'info': vt_lookup[src_ip6]})
                if dst_ip6 in vt_lookup and dst_ip6 not in [t['entity'] for t in threats_in_chunk]:
                    threats_in_chunk.append({'entity': dst_ip6, 'info': vt_lookup[dst_ip6]})

            if 'dns' in packet and 'query_name' in packet['dns']:
                query_domain = packet['dns']['query_name']
                domains.add(query_domain)
                if query_domain in vt_lookup and query_domain not in [t['entity'] for t in threats_in_chunk]:
                    threats_in_chunk.append({'entity': query_domain, 'info': vt_lookup[query_domain]})

            if 'http' in packet and 'host' in packet['http']:
                http_host = packet['http']['host']
                domains.add(http_host)
                if http_host in vt_lookup and http_host not in [t['entity'] for t in threats_in_chunk]:
                    threats_in_chunk.append({'entity': http_host, 'info': vt_lookup[http_host]})

            if 'protocol' in packet:
                protocols.add(packet['protocol'])

            if 'timestamp' in packet:
                timestamps.append(packet['timestamp'])

        chunk_text = self._format_chunk_for_embedding(packets, ips, domains, protocols, threats_in_chunk)

        return {
            'chunk_index': chunk_index,
            'packet_range': {'start': start_idx, 'end': end_idx},
            'chunk_text': chunk_text,
            'metadata': {
                'ip_addresses': list(ips),
                'domains': list(domains),
                'protocols': list(protocols),
                'timestamp_range': {
                    'start': timestamps[0] if timestamps else None,
                    'end': timestamps[-1] if timestamps else None
                },
                'packet_count': len(packets),
                'threat_count': len(threats_in_chunk),
                'has_threats': len(threats_in_chunk) > 0,
                'chunk_type': 'packet_data'
            }
        }

    def _format_chunk_for_embedding(self, packets: List[Dict[str, Any]], ips: set, domains: set, protocols: set, threats: List[Dict[str, Any]]) -> str:
        text_parts = []

        text_parts.append(f"Network traffic segment with {len(packets)} packets.")

        if threats:
            text_parts.append(f"\n=== VIRUSTOTAL THREAT INTELLIGENCE ({len(threats)} threats detected) ===")
            for threat in threats[:10]:
                entity = threat['entity']
                info = threat['info']
                threat_desc = f"THREAT DETECTED: {info['type'].upper()} {entity} "
                threat_desc += f"flagged by {info['malicious_count']} security vendors"
                if info.get('threat_label'):
                    threat_desc += f" as {info['threat_label']}"
                if info.get('suspicious_count', 0) > 0:
                    threat_desc += f" (suspicious: {info['suspicious_count']})"
                if info.get('categories'):
                    threat_desc += f". Categories: {', '.join(info['categories'][:3])}"
                text_parts.append(threat_desc)
            text_parts.append("")

        protocol_list = list(protocols)
        if protocol_list:
            text_parts.append(f"Protocols observed: {', '.join(protocol_list)}")

        ip_list = list(ips)
        if ip_list:
            text_parts.append(f"IP addresses involved: {', '.join(ip_list[:15])}")

        domain_list = list(domains)
        if domain_list:
            text_parts.append(f"Domain names accessed: {', '.join(domain_list[:15])}")

        http_requests = []
        dns_queries = []
        tcp_flags_summary = []
        tls_connections = []

        for packet in packets:
            if 'http' in packet:
                http_info = packet['http']
                method = http_info.get('method', 'GET')
                host = http_info.get('host', 'unknown')
                uri = http_info.get('uri', '/')
                status = http_info.get('status_code', '')
                request_desc = f"{method} {host}{uri}"
                if status:
                    request_desc += f" (Status: {status})"
                http_requests.append(request_desc)

            if 'dns' in packet:
                query_name = packet['dns'].get('query_name', '')
                query_type = packet['dns'].get('query_type', '')
                answer = packet['dns'].get('answer', '')
                if query_name:
                    dns_desc = f"{query_name}"
                    if query_type:
                        dns_desc += f" (Type: {query_type})"
                    if answer:
                        dns_desc += f" -> {answer}"
                    dns_queries.append(dns_desc)

            if 'tcp' in packet:
                flags = packet['tcp'].get('flags')
                if flags:
                    src = packet.get('ip', {}).get('src', 'Unknown')
                    dst = packet.get('ip', {}).get('dst', 'Unknown')
                    src_port = packet['tcp'].get('src_port')
                    dst_port = packet['tcp'].get('dst_port')
                    tcp_flags_summary.append(f"{src}:{src_port} -> {dst}:{dst_port} [Flags: {flags}]")

            if 'tls' in packet:
                handshake = packet['tls'].get('handshake_type', '')
                version = packet['tls'].get('version', '')
                if handshake or version:
                    tls_connections.append(f"TLS handshake: {handshake} Version: {version}")

        if http_requests:
            text_parts.append(f"HTTP activity: {'; '.join(http_requests[:8])}")

        if dns_queries:
            text_parts.append(f"DNS lookups: {'; '.join(dns_queries[:12])}")

        if tcp_flags_summary[:3]:
            text_parts.append(f"TCP connections: {'; '.join(tcp_flags_summary[:3])}")

        if tls_connections[:3]:
            text_parts.append(f"TLS sessions: {'; '.join(tls_connections[:3])}")

        flow_summary = []
        for packet in packets[:8]:
            src = packet.get('ip', {}).get('src', packet.get('ipv6', {}).get('src', 'N/A'))
            dst = packet.get('ip', {}).get('dst', packet.get('ipv6', {}).get('dst', 'N/A'))
            proto = packet.get('protocol', 'UNKNOWN')
            length = packet.get('length', 0)
            flow_summary.append(f"{src} -> {dst} ({proto}, {length} bytes)")

        if flow_summary:
            text_parts.append(f"Traffic flows: {'; '.join(flow_summary)}")

        return " ".join(text_parts)

    def chunk_by_flow(self, full_json_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        packets = full_json_data.get('packets', [])
        if not packets:
            return []

        flow_groups = {}

        for packet in packets:
            src = packet.get('ip', {}).get('src', packet.get('ipv6', {}).get('src', 'N/A'))
            dst = packet.get('ip', {}).get('dst', packet.get('ipv6', {}).get('dst', 'N/A'))
            flow_key = f"{src}->{dst}"

            if flow_key not in flow_groups:
                flow_groups[flow_key] = []
            flow_groups[flow_key].append(packet)

        chunks = []
        chunk_index = 0

        for flow_key, flow_packets in flow_groups.items():
            for i in range(0, len(flow_packets), self.max_chunk_size):
                chunk_packets = flow_packets[i:i + self.max_chunk_size]
                chunk = self._create_chunk(chunk_packets, chunk_index, i, min(i + self.max_chunk_size, len(flow_packets)))
                chunk['flow_key'] = flow_key
                chunks.append(chunk)
                chunk_index += 1

        return chunks

    def validate_chunk_size(self, chunk_text: str, max_tokens: int = 2048) -> bool:
        estimated_tokens = len(chunk_text.split())
        return estimated_tokens <= max_tokens

    def _create_threat_intelligence_chunks(self, vt_results: Dict[str, Any], start_index: int) -> List[Dict[str, Any]]:
        chunks = []
        chunk_index = start_index

        if not vt_results or 'results' not in vt_results:
            return chunks

        threat_data = []
        for entity_type, entities in vt_results['results'].items():
            for entity_value, entity_data in entities.items():
                if entity_data and (entity_data.get('malicious', 0) > 0 or entity_data.get('suspicious', 0) > 0):
                    threat_data.append({
                        'type': entity_type,
                        'value': entity_value,
                        'data': entity_data
                    })

        if not threat_data:
            return chunks

        threat_chunk_size = 10
        for i in range(0, len(threat_data), threat_chunk_size):
            batch = threat_data[i:i + threat_chunk_size]
            chunk_text = self._format_threat_intelligence_chunk(batch)

            chunk = {
                'chunk_index': chunk_index,
                'packet_range': {'start': -1, 'end': -1},
                'chunk_text': chunk_text,
                'metadata': {
                    'ip_addresses': [t['value'] for t in batch if t['type'] == 'ip'],
                    'domains': [t['value'] for t in batch if t['type'] == 'domain'],
                    'protocols': [],
                    'timestamp_range': {'start': None, 'end': None},
                    'packet_count': 0,
                    'threat_count': len(batch),
                    'has_threats': True,
                    'chunk_type': 'threat_intelligence'
                }
            }
            chunks.append(chunk)
            chunk_index += 1

        return chunks

    def _format_threat_intelligence_chunk(self, threats: List[Dict[str, Any]]) -> str:
        text_parts = []

        text_parts.append("=== VIRUSTOTAL THREAT INTELLIGENCE DATA ===")
        text_parts.append(f"This chunk contains threat intelligence for {len(threats)} entities queried from VirusTotal.")
        text_parts.append("The following IPs, domains, and file hashes were analyzed and flagged by security vendors:")
        text_parts.append("")

        for threat in threats:
            entity_type = threat['type'].upper()
            entity_value = threat['value']
            data = threat['data']

            malicious_count = data.get('malicious', 0)
            suspicious_count = data.get('suspicious', 0)
            threat_label = data.get('threat_label', 'Unknown')
            categories = data.get('categories', [])

            threat_desc = f"THREAT: {entity_type} {entity_value}\n"
            threat_desc += f"  - Flagged as MALICIOUS by {malicious_count} security vendors\n"
            if suspicious_count > 0:
                threat_desc += f"  - Flagged as SUSPICIOUS by {suspicious_count} vendors\n"
            if threat_label and threat_label != 'Unknown':
                threat_desc += f"  - Threat Label: {threat_label}\n"
            if categories:
                threat_desc += f"  - Categories: {', '.join(categories[:5])}\n"

            if entity_type == 'FILE':
                if data.get('detection_engines'):
                    threat_desc += f"  - Detection Engines: "
                    engines = [f"{e['engine']}:{e['result']}" for e in data['detection_engines'][:3]]
                    threat_desc += ", ".join(engines) + "\n"

            text_parts.append(threat_desc)

        text_parts.append("")
        text_parts.append("NOTE: This threat intelligence data was obtained from VirusTotal and represents")
        text_parts.append("confirmed threats detected in the analyzed network traffic.")

        return "\n".join(text_parts)

    def _create_forensic_metadata_chunk(self, forensic_data: Dict[str, Any], chunk_index: int) -> Dict[str, Any]:
        """Create a priority chunk with forensic investigation data for easy RAG retrieval."""
        text_parts = []

        text_parts.append("=== FORENSIC INVESTIGATION METADATA ===")
        text_parts.append("This chunk contains critical host identification and infection timeline data extracted from network traffic analysis.")
        text_parts.append("")

        # Find infected hosts
        infected_hosts = {ip: host for ip, host in forensic_data.get('hosts', {}).items() if host.get('is_infected')}

        if infected_hosts:
            for ip, host_info in infected_hosts.items():
                text_parts.append("=== INFECTED HOST IDENTIFIED ===")
                text_parts.append(f"IP Address: {ip}")

                if host_info.get('mac_addresses'):
                    mac = host_info['mac_addresses'][0]
                    text_parts.append(f"MAC Address: {mac}")
                    text_parts.append(f"Hardware Address: {mac}")
                    text_parts.append(f"Physical Address: {mac}")
                    text_parts.append(f"Ethernet Address: {mac}")

                if host_info.get('hostnames'):
                    hostname = host_info['hostnames'][0]
                    text_parts.append(f"Hostname: {hostname}")
                    text_parts.append(f"Computer Name: {hostname}")
                    text_parts.append(f"Machine Name: {hostname}")
                    text_parts.append(f"Workstation Name: {hostname}")
                    if len(host_info['hostnames']) > 1:
                        text_parts.append(f"All observed hostnames: {', '.join(host_info['hostnames'])}")

                if host_info.get('netbios_names'):
                    text_parts.append(f"NetBIOS Names: {', '.join(host_info['netbios_names'])}")

                if host_info.get('user_accounts'):
                    user = host_info['user_accounts'][0]
                    text_parts.append(f"User Account: {user}")
                    text_parts.append(f"Username: {user}")
                    text_parts.append(f"Authenticated User: {user}")
                    text_parts.append(f"Logged in User: {user}")
                    text_parts.append(f"Account Name: {user}")
                    if len(host_info['user_accounts']) > 1:
                        text_parts.append(f"All observed users: {', '.join(host_info['user_accounts'])}")

                if host_info.get('domains'):
                    domain = host_info['domains'][0]
                    text_parts.append(f"Domain: {domain}")
                    text_parts.append(f"Windows Domain: {domain}")
                    text_parts.append(f"Active Directory Domain: {domain}")
                    text_parts.append(f"Realm: {domain}")
                    text_parts.append(f"Workgroup: {domain}")

                if host_info.get('os_versions'):
                    os_version = host_info['os_versions'][0]
                    text_parts.append(f"Operating System: {os_version}")
                    text_parts.append(f"OS Version: {os_version}")
                    text_parts.append(f"Windows Version: {os_version}")
                    text_parts.append(f"System Information: {os_version}")

                if host_info.get('first_seen'):
                    text_parts.append(f"First Activity: {host_info['first_seen']}")
                    text_parts.append(f"First Seen: {host_info['first_seen']}")
                    text_parts.append(f"Initial Activity Timestamp: {host_info['first_seen']}")

                if host_info.get('last_seen'):
                    text_parts.append(f"Last Activity: {host_info['last_seen']}")
                    text_parts.append(f"Last Seen: {host_info['last_seen']}")

                text_parts.append(f"Total Packets: {host_info.get('total_packets', 0)}")
                text_parts.append(f"Compromised: YES")
                text_parts.append(f"Infection Status: INFECTED")
                text_parts.append(f"Threat Detected: YES")
                text_parts.append("")

                # Add malicious connections
                if host_info.get('malicious_connections'):
                    text_parts.append("MALICIOUS ACTIVITY DETECTED:")
                    for conn in host_info['malicious_connections'][:10]:
                        text_parts.append(f"  [{conn.get('timestamp', 'N/A')}] Connected to malicious {conn.get('type', 'entity')}: {conn.get('value', 'unknown')}")
                    text_parts.append("")

        # Add all hosts (including non-infected) for reference
        all_hosts = forensic_data.get('hosts', {})
        if all_hosts:
            text_parts.append("=== ALL HOSTS IN NETWORK ===")
            for ip, host_info in list(all_hosts.items())[:20]:  # Limit to 20 hosts
                host_desc = f"Host {ip}"
                if host_info.get('hostnames'):
                    host_desc += f" (Hostname: {host_info['hostnames'][0]})"
                if host_info.get('mac_addresses'):
                    host_desc += f" [MAC: {host_info['mac_addresses'][0]}]"
                if host_info.get('user_accounts'):
                    host_desc += f" User: {host_info['user_accounts'][0]}"
                text_parts.append(host_desc)
            text_parts.append("")

        # Add infection timeline
        if forensic_data.get('infection_timeline'):
            text_parts.append("=== INFECTION TIMELINE ===")
            text_parts.append("Chronological sequence of malware infection events:")
            text_parts.append("")
            for event in forensic_data['infection_timeline'][:15]:  # Limit to first 15 events
                timestamp = event.get('timestamp', 'N/A')
                description = event.get('description', 'Unknown event')
                text_parts.append(f"[{timestamp}] {description}")
            text_parts.append("")

        # Add ARP table
        if forensic_data.get('arp_table'):
            text_parts.append("=== ARP TABLE (MAC to IP Mappings) ===")
            for ip, mac in list(forensic_data['arp_table'].items())[:15]:
                text_parts.append(f"{ip} -> {mac}")
            text_parts.append("")

        # Add network topology
        if forensic_data.get('network_topology'):
            topo = forensic_data['network_topology']
            if topo.get('internal_ips'):
                text_parts.append(f"Internal Network IPs: {', '.join(topo['internal_ips'][:10])}")
            if topo.get('external_ips'):
                text_parts.append(f"External IPs Contacted: {len(topo['external_ips'])} unique addresses")

        text_parts.append("")
        text_parts.append("NOTE: This forensic metadata was extracted from multiple protocol layers including:")
        text_parts.append("- Layer 2 (Ethernet/MAC addresses)")
        text_parts.append("- DHCP (hostname, domain name)")
        text_parts.append("- NetBIOS/NBNS (computer name, workgroup)")
        text_parts.append("- Kerberos (user authentication, realm)")
        text_parts.append("- SMB/SMB2 (OS version, domain, file access)")
        text_parts.append("- ARP (MAC to IP mappings)")
        text_parts.append("- Combined with VirusTotal threat intelligence")

        return {
            'chunk_index': chunk_index,
            'packet_range': {'start': -1, 'end': -1},
            'chunk_text': '\n'.join(text_parts),
            'metadata': {
                'chunk_type': 'forensic_metadata',
                'has_forensic_data': True,
                'priority': 'highest',
                'infected_host_count': len(infected_hosts) if infected_hosts else 0,
                'total_host_count': len(all_hosts),
                'has_timeline': bool(forensic_data.get('infection_timeline')),
                'ip_addresses': list(infected_hosts.keys()) if infected_hosts else [],
                'domains': [],
                'protocols': [],
                'timestamp_range': {'start': None, 'end': None},
                'packet_count': 0,
                'threat_count': len(infected_hosts) if infected_hosts else 0,
                'has_threats': bool(infected_hosts)
            }
        }

    def extract_metadata_from_chunk(self, chunk: Dict[str, Any]) -> Dict[str, Any]:
        return chunk.get('metadata', {})
