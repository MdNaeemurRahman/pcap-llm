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

        # Create multiple focused forensic chunks FIRST for priority retrieval
        if full_json_data.get('forensic_analysis'):
            forensic_data = full_json_data['forensic_analysis']

            # Chunk 0: Investigation narrative (optional lightweight Q&A summary)
            if forensic_data.get('infected_hosts'):
                narrative_chunk = self.generate_investigation_narrative(forensic_data, chunk_index)
                chunks.append(narrative_chunk)
                chunk_index += 1

            # Chunk 1+: Primary infected host identification (highest priority)
            if forensic_data.get('infected_hosts'):
                for infected_host in forensic_data['infected_hosts'][:2]:  # Top 2 infected hosts
                    host_id_chunk = self._create_infected_host_id_chunk(infected_host, chunk_index)
                    chunks.append(host_id_chunk)
                    chunk_index += 1

            # Chunk N+1: Infection timeline (if available)
            if forensic_data.get('infection_timeline'):
                timeline_chunk = self._create_infection_timeline_chunk(forensic_data, chunk_index)
                chunks.append(timeline_chunk)
                chunk_index += 1

            # Chunk N+2: All hosts inventory (lower priority)
            if forensic_data.get('hosts'):
                hosts_chunk = self._create_all_hosts_inventory_chunk(forensic_data, chunk_index)
                chunks.append(hosts_chunk)
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

    def _create_infected_host_id_chunk(self, infected_host: Dict[str, Any], chunk_index: int) -> Dict[str, Any]:
        """Create focused chunk for infected host identification with extensive keyword repetition."""
        text_parts = []

        ip = infected_host['ip']
        mac = infected_host.get('mac', 'Unknown')
        hostname = infected_host.get('hostname', 'Unknown')
        user = infected_host.get('user_account', 'Unknown')
        domain = infected_host.get('domain', 'Unknown')
        os_info = infected_host.get('os_info', 'Unknown')

        # Header
        text_parts.append("=== INFECTED HOST IDENTIFICATION ===")
        text_parts.append("Critical forensic information about the compromised system:")
        text_parts.append("")

        # IP Address section with extensive repetition
        text_parts.append("=== IP ADDRESS ===")
        text_parts.append(f"The infected client IP address is {ip}")
        text_parts.append(f"The compromised machine has IP {ip}")
        text_parts.append(f"The victim computer IP address: {ip}")
        text_parts.append(f"Infected host IP: {ip}")
        text_parts.append(f"The Windows client is at IP {ip}")
        text_parts.append(f"IP of infected system: {ip}")
        text_parts.append("")

        # MAC Address section with extensive repetition
        if mac != 'Unknown':
            text_parts.append("=== MAC ADDRESS / HARDWARE ADDRESS ===")
            text_parts.append(f"The infected client MAC address is {mac}")
            text_parts.append(f"The compromised machine hardware address: {mac}")
            text_parts.append(f"Physical address of infected host: {mac}")
            text_parts.append(f"Ethernet address: {mac}")
            text_parts.append(f"Layer 2 address: {mac}")
            text_parts.append(f"NIC address of infected client: {mac}")
            text_parts.append(f"The victim computer's MAC address is {mac}")
            source = infected_host.get('data_sources', {}).get('mac', 'network analysis')
            text_parts.append(f"This MAC address was identified through {source}")
            text_parts.append("")

        # Hostname section with extensive repetition
        if hostname != 'Unknown':
            text_parts.append("=== HOSTNAME / COMPUTER NAME ===")
            text_parts.append(f"The infected client hostname is {hostname}")
            text_parts.append(f"The compromised machine computer name: {hostname}")
            text_parts.append(f"The Windows client name: {hostname}")
            text_parts.append(f"Infected host hostname: {hostname}")
            text_parts.append(f"Machine name: {hostname}")
            text_parts.append(f"Workstation name: {hostname}")
            text_parts.append(f"Device name: {hostname}")
            text_parts.append(f"The victim computer is named {hostname}")
            text_parts.append(f"Computer identification: {hostname}")
            source = infected_host.get('data_sources', {}).get('hostname', 'network protocol')
            text_parts.append(f"This hostname was discovered through {source}")

            # Add alternate names if available
            if infected_host.get('all_hostnames'):
                text_parts.append(f"Alternative names observed: {', '.join(infected_host['all_hostnames'][:3])}")
            if infected_host.get('netbios_names'):
                text_parts.append(f"NetBIOS names: {', '.join(infected_host['netbios_names'][:3])}")
            text_parts.append("")

        # User Account section with extensive repetition
        if user != 'Unknown':
            text_parts.append("=== USER ACCOUNT / USERNAME ===")
            text_parts.append(f"The user account on infected client: {user}")
            text_parts.append(f"The logged in user: {user}")
            text_parts.append(f"Username on compromised system: {user}")
            text_parts.append(f"Authenticated user: {user}")
            text_parts.append(f"Account name: {user}")
            text_parts.append(f"The person logged into infected host: {user}")
            text_parts.append(f"Active user account: {user}")
            source = infected_host.get('data_sources', {}).get('user_account', 'authentication protocol')
            text_parts.append(f"This user account was identified through {source}")

            # Add alternate users if available
            if infected_host.get('all_users'):
                text_parts.append(f"Other users observed: {', '.join(infected_host['all_users'][:3])}")
            text_parts.append("")

        # Domain section
        if domain != 'Unknown':
            text_parts.append("=== DOMAIN / WORKGROUP ===")
            text_parts.append(f"Domain: {domain}")
            text_parts.append(f"Windows domain: {domain}")
            text_parts.append(f"Active Directory domain: {domain}")
            text_parts.append(f"Realm: {domain}")
            text_parts.append(f"Workgroup: {domain}")
            source = infected_host.get('data_sources', {}).get('domain', 'network protocol')
            text_parts.append(f"This domain was identified through {source}")
            text_parts.append("")

        # Operating System section
        if os_info != 'Unknown':
            text_parts.append("=== OPERATING SYSTEM ===")
            text_parts.append(f"Operating system: {os_info}")
            text_parts.append(f"OS version: {os_info}")
            text_parts.append(f"Windows version: {os_info}")
            text_parts.append(f"System information: {os_info}")
            source = infected_host.get('data_sources', {}).get('os_info', 'SMB protocol')
            text_parts.append(f"This OS information was obtained from {source}")
            text_parts.append("")

        # Infection status
        text_parts.append("=== INFECTION STATUS ===")
        text_parts.append(f"Status: INFECTED / COMPROMISED")
        text_parts.append(f"Threat detected: YES")
        text_parts.append(f"Infection confidence: {infected_host.get('infection_confidence', 'unknown')}")
        text_parts.append(f"Malicious connections: {infected_host.get('malicious_connections_count', 0)}")
        text_parts.append(f"First seen: {infected_host.get('first_seen', 'Unknown')}")
        text_parts.append(f"Total packets: {infected_host.get('total_packets', 0)}")
        text_parts.append("")

        # Add Q&A format for direct matching
        text_parts.append("=== QUICK ANSWERS ===")
        text_parts.append(f"Q: What is the IP address of the infected client?")
        text_parts.append(f"A: {ip}")
        text_parts.append(f"Q: What is the MAC address of the infected client?")
        text_parts.append(f"A: {mac}")
        text_parts.append(f"Q: What is the hostname of the infected client?")
        text_parts.append(f"A: {hostname}")
        text_parts.append(f"Q: What is the user account name from the infected host?")
        text_parts.append(f"A: {user}")
        text_parts.append("")

        # Summary paragraph
        text_parts.append("=== SUMMARY ===")
        summary = f"The infected Windows client at IP address {ip}"
        if hostname != 'Unknown':
            summary += f" with hostname {hostname}"
        if mac != 'Unknown':
            summary += f" and MAC address {mac}"
        summary += " has been compromised."
        if user != 'Unknown':
            summary += f" The user account {user} was logged in when the infection occurred."
        text_parts.append(summary)

        return {
            'chunk_index': chunk_index,
            'packet_range': {'start': -1, 'end': -1},
            'chunk_text': '\n'.join(text_parts),
            'metadata': {
                'chunk_type': 'infected_host_identification',
                'has_forensic_data': True,
                'priority': 'highest',
                'infected_ip': ip,
                'hostname': hostname,
                'mac_address': mac,
                'user_account': user,
                'ip_addresses': [ip],
                'domains': [domain] if domain != 'Unknown' else [],
                'protocols': [],
                'timestamp_range': {'start': None, 'end': None},
                'packet_count': 0,
                'threat_count': 1,
                'has_threats': True
            }
        }

    def _create_infection_timeline_chunk(self, forensic_data: Dict[str, Any], chunk_index: int) -> Dict[str, Any]:
        """Create focused chunk for infection timeline."""
        text_parts = []

        text_parts.append("=== INFECTION TIMELINE ===")
        text_parts.append("Chronological sequence of malware infection events:")
        text_parts.append("")

        timeline = forensic_data.get('infection_timeline', [])
        for event in timeline[:15]:
            timestamp = event.get('timestamp', 'N/A')
            description = event.get('description', 'Unknown event')
            text_parts.append(f"[{timestamp}] {description}")

        text_parts.append("")
        text_parts.append(f"Total timeline events: {len(timeline)}")

        return {
            'chunk_index': chunk_index,
            'packet_range': {'start': -1, 'end': -1},
            'chunk_text': '\n'.join(text_parts),
            'metadata': {
                'chunk_type': 'infection_timeline',
                'has_forensic_data': True,
                'priority': 'high',
                'ip_addresses': [],
                'domains': [],
                'protocols': [],
                'timestamp_range': {'start': None, 'end': None},
                'packet_count': 0,
                'threat_count': 0,
                'has_threats': False
            }
        }

    def _create_all_hosts_inventory_chunk(self, forensic_data: Dict[str, Any], chunk_index: int) -> Dict[str, Any]:
        """Create focused chunk for all network hosts inventory."""
        text_parts = []

        text_parts.append("=== ALL NETWORK HOSTS INVENTORY ===")
        text_parts.append("Complete list of hosts identified in the network:")
        text_parts.append("")

        all_hosts = forensic_data.get('hosts', {})
        for ip, host_info in list(all_hosts.items())[:30]:
            host_desc = f"Host {ip}"
            if host_info.get('hostnames'):
                host_desc += f" - Hostname: {host_info['hostnames'][0]}"
            if host_info.get('mac_addresses'):
                host_desc += f" - MAC: {host_info['mac_addresses'][0]}"
            if host_info.get('user_accounts'):
                host_desc += f" - User: {host_info['user_accounts'][0]}"
            host_desc += f" - Status: {'INFECTED' if host_info.get('is_infected') else 'Clean'}"
            text_parts.append(host_desc)

        text_parts.append("")
        text_parts.append(f"Total hosts: {len(all_hosts)}")

        # ARP table
        if forensic_data.get('arp_table'):
            text_parts.append("")
            text_parts.append("=== ARP TABLE (MAC to IP Mappings) ===")
            for ip, mac in list(forensic_data['arp_table'].items())[:20]:
                text_parts.append(f"{ip} -> {mac}")

        return {
            'chunk_index': chunk_index,
            'packet_range': {'start': -1, 'end': -1},
            'chunk_text': '\n'.join(text_parts),
            'metadata': {
                'chunk_type': 'hosts_inventory',
                'has_forensic_data': True,
                'priority': 'medium',
                'ip_addresses': list(all_hosts.keys())[:20],
                'domains': [],
                'protocols': [],
                'timestamp_range': {'start': None, 'end': None},
                'packet_count': 0,
                'threat_count': 0,
                'has_threats': False
            }
        }

    def generate_investigation_narrative(self, forensic_data: Dict[str, Any], chunk_index: int) -> Dict[str, Any]:
        """Generate a natural language narrative summary for optimal RAG retrieval (optional lightweight chunk)."""
        narrative = []
        narrative.append("=== FORENSIC INVESTIGATION NARRATIVE ===\n")

        infected_hosts = forensic_data.get('infected_hosts', [])

        if infected_hosts:
            infected = infected_hosts[0]  # Primary infected host

            # Create narrative in natural question-answer language
            narrative.append("Investigation reveals the following about the compromised system:\n")

            narrative.append(f"The infected Windows client can be identified by IP address {infected['ip']}.")
            narrative.append(f"When asked about the infected client's IP, the answer is: {infected['ip']}")
            narrative.append(f"The compromised host IP address is {infected['ip']}\n")

            if infected.get('hostname', 'Unknown') != 'Unknown':
                hostname = infected['hostname']
                narrative.append(f"The computer name of this infected machine is {hostname}.")
                narrative.append(f"When asked about the hostname of the infected client, the answer is: {hostname}")
                narrative.append(f"This hostname was discovered through {infected.get('data_sources', {}).get('hostname', 'DHCP protocol analysis')}.\n")

            if infected.get('mac', 'Unknown') != 'Unknown':
                mac = infected['mac']
                narrative.append(f"The hardware address (MAC address) of the compromised system is {mac}.")
                narrative.append(f"When asked about the MAC address of the infected client, the answer is: {mac}")
                narrative.append(f"This physical address was obtained from {infected.get('data_sources', {}).get('mac', 'ARP table analysis')}.\n")

            if infected.get('user_account', 'Unknown') != 'Unknown':
                user = infected['user_account']
                narrative.append(f"The user account logged into the infected system was {user}.")
                narrative.append(f"When asked about the user account name from the infected host, the answer is: {user}")
                narrative.append(f"This username was identified through {infected.get('data_sources', {}).get('user_account', 'Kerberos authentication records')}.\n")

            if infected.get('domain', 'Unknown') != 'Unknown':
                domain = infected['domain']
                narrative.append(f"The Windows domain is {domain}.\n")

            if infected.get('os_info', 'Unknown') != 'Unknown':
                os_info = infected['os_info']
                narrative.append(f"The operating system detected is {os_info}.\n")

            # Add common investigation questions section
            narrative.append("\n=== COMMON FORENSIC QUESTIONS & ANSWERS ===")
            narrative.append(f"Q: What is the IP of the infected client?")
            narrative.append(f"A: {infected['ip']}\n")

            narrative.append(f"Q: What is the hostname of the infected Windows client?")
            narrative.append(f"A: {infected.get('hostname', 'Unknown')}\n")

            narrative.append(f"Q: What is the MAC address of the infected client?")
            narrative.append(f"A: {infected.get('mac', 'Unknown')}\n")

            narrative.append(f"Q: What is the user account name from the infected host?")
            narrative.append(f"A: {infected.get('user_account', 'Unknown')}\n")

            narrative.append(f"Q: What is the domain?")
            narrative.append(f"A: {infected.get('domain', 'Unknown')}\n")

            # Add consolidated summary
            narrative.append("\n=== INVESTIGATION SUMMARY ===")
            summary = f"In summary: The infected system is a Windows client at IP {infected['ip']}"
            if infected.get('hostname', 'Unknown') != 'Unknown':
                summary += f", named {infected['hostname']}"
            if infected.get('mac', 'Unknown') != 'Unknown':
                summary += f", with MAC address {infected['mac']}"
            if infected.get('user_account', 'Unknown') != 'Unknown':
                summary += f", where user {infected['user_account']} was logged in"
            summary += ". This host has been compromised and connected to malicious external entities."
            narrative.append(summary)
        else:
            narrative.append("No infected hosts were identified in this analysis.")

        return {
            'chunk_index': chunk_index,
            'packet_range': {'start': -1, 'end': -1},
            'chunk_text': '\n'.join(narrative),
            'metadata': {
                'chunk_type': 'investigation_narrative',
                'has_forensic_data': True,
                'priority': 'highest',
                'ip_addresses': [infected['ip']] if infected_hosts else [],
                'domains': [],
                'protocols': [],
                'timestamp_range': {'start': None, 'end': None},
                'packet_count': 0,
                'threat_count': 1 if infected_hosts else 0,
                'has_threats': bool(infected_hosts)
            }
        }

    def extract_metadata_from_chunk(self, chunk: Dict[str, Any]) -> Dict[str, Any]:
        return chunk.get('metadata', {})
