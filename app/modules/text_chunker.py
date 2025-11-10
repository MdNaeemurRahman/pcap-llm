import json
from typing import Dict, List, Any, Optional


class TextChunker:
    def __init__(self, max_chunk_size: int = 100):
        self.max_chunk_size = max_chunk_size

    def chunk_by_packet_range(self, full_json_data: Dict[str, Any], vt_results: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        packets = full_json_data.get('packets', [])
        if not packets:
            return []

        chunks = []
        chunk_index = 0

        vt_lookup = self._build_vt_lookup(vt_results) if vt_results else {}

        for i in range(0, len(packets), self.max_chunk_size):
            chunk_packets = packets[i:i + self.max_chunk_size]
            chunk = self._create_chunk(chunk_packets, chunk_index, i, min(i + self.max_chunk_size, len(packets)), vt_lookup)
            chunks.append(chunk)
            chunk_index += 1

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
                'has_threats': len(threats_in_chunk) > 0
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

    def extract_metadata_from_chunk(self, chunk: Dict[str, Any]) -> Dict[str, Any]:
        return chunk.get('metadata', {})
