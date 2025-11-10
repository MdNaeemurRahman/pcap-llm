import json
from typing import Dict, List, Any


class TextChunker:
    def __init__(self, max_chunk_size: int = 100):
        self.max_chunk_size = max_chunk_size

    def chunk_by_packet_range(self, full_json_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        packets = full_json_data.get('packets', [])
        if not packets:
            return []

        chunks = []
        chunk_index = 0

        for i in range(0, len(packets), self.max_chunk_size):
            chunk_packets = packets[i:i + self.max_chunk_size]
            chunk = self._create_chunk(chunk_packets, chunk_index, i, min(i + self.max_chunk_size, len(packets)))
            chunks.append(chunk)
            chunk_index += 1

        return chunks

    def _create_chunk(self, packets: List[Dict[str, Any]], chunk_index: int, start_idx: int, end_idx: int) -> Dict[str, Any]:
        ips = set()
        domains = set()
        protocols = set()
        timestamps = []

        for packet in packets:
            if 'ip' in packet:
                ips.add(packet['ip']['src'])
                ips.add(packet['ip']['dst'])
            if 'ipv6' in packet:
                ips.add(packet['ipv6']['src'])
                ips.add(packet['ipv6']['dst'])

            if 'dns' in packet and 'query_name' in packet['dns']:
                domains.add(packet['dns']['query_name'])
            if 'http' in packet and 'host' in packet['http']:
                domains.add(packet['http']['host'])

            if 'protocol' in packet:
                protocols.add(packet['protocol'])

            if 'timestamp' in packet:
                timestamps.append(packet['timestamp'])

        chunk_text = self._format_chunk_for_embedding(packets, ips, domains, protocols)

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
                'packet_count': len(packets)
            }
        }

    def _format_chunk_for_embedding(self, packets: List[Dict[str, Any]], ips: set, domains: set, protocols: set) -> str:
        text_parts = []

        text_parts.append(f"Network traffic chunk containing {len(packets)} packets.")
        text_parts.append(f"Protocols: {', '.join(protocols)}")
        text_parts.append(f"Unique IP addresses: {', '.join(list(ips)[:20])}")
        if domains:
            text_parts.append(f"Domains accessed: {', '.join(list(domains)[:20])}")

        http_requests = []
        dns_queries = []

        for packet in packets:
            if 'http' in packet:
                http_info = packet['http']
                method = http_info.get('method', 'GET')
                host = http_info.get('host', 'unknown')
                uri = http_info.get('uri', '/')
                http_requests.append(f"{method} {host}{uri}")

            if 'dns' in packet:
                query = packet['dns'].get('query_name', '')
                if query:
                    dns_queries.append(query)

        if http_requests:
            text_parts.append(f"HTTP requests: {', '.join(http_requests[:10])}")
        if dns_queries:
            text_parts.append(f"DNS queries: {', '.join(dns_queries[:10])}")

        flow_summary = []
        for packet in packets[:5]:
            src = packet.get('ip', {}).get('src', packet.get('ipv6', {}).get('src', 'N/A'))
            dst = packet.get('ip', {}).get('dst', packet.get('ipv6', {}).get('dst', 'N/A'))
            proto = packet.get('protocol', 'UNKNOWN')
            flow_summary.append(f"{src} -> {dst} ({proto})")

        text_parts.append(f"Sample flows: {', '.join(flow_summary)}")

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
