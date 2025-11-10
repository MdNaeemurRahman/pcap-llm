import hashlib
import json
from pathlib import Path
from typing import Dict, List, Tuple, Any
from collections import Counter
import pyshark


class PCAPParser:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.capture = None
        self.packets_data = []

    def compute_file_hash(self) -> str:
        sha256_hash = hashlib.sha256()
        with open(self.file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def load_capture(self):
        try:
            self.capture = pyshark.FileCapture(self.file_path)
        except Exception as e:
            raise Exception(f"Failed to load PCAP file: {str(e)}")

    def extract_basic_stats(self) -> Dict[str, Any]:
        if not self.capture:
            self.load_capture()

        stats = {
            'total_packets': 0,
            'protocols': Counter(),
            'unique_ips': set(),
            'unique_domains': set()
        }

        try:
            for packet in self.capture:
                stats['total_packets'] += 1

                if hasattr(packet, 'highest_layer'):
                    stats['protocols'][packet.highest_layer] += 1

                if hasattr(packet, 'ip'):
                    stats['unique_ips'].add(packet.ip.src)
                    stats['unique_ips'].add(packet.ip.dst)
                elif hasattr(packet, 'ipv6'):
                    stats['unique_ips'].add(packet.ipv6.src)
                    stats['unique_ips'].add(packet.ipv6.dst)

                if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
                    stats['unique_domains'].add(packet.dns.qry_name)

                if hasattr(packet, 'http') and hasattr(packet.http, 'host'):
                    stats['unique_domains'].add(packet.http.host)
        except Exception as e:
            print(f"Warning during stats extraction: {str(e)}")
        finally:
            self.capture.close()
            self.capture = None

        return {
            'total_packets': stats['total_packets'],
            'top_protocols': dict(stats['protocols'].most_common(10)),
            'unique_ips': list(stats['unique_ips']),
            'unique_domains': list(stats['unique_domains']),
            'unique_ips_count': len(stats['unique_ips']),
            'unique_domains_count': len(stats['unique_domains'])
        }

    def parse_network_flows(self) -> List[Dict[str, Any]]:
        if not self.capture:
            self.load_capture()

        flows = []
        flow_counter = Counter()

        try:
            for packet in self.capture:
                flow_data = {
                    'timestamp': str(packet.sniff_time) if hasattr(packet, 'sniff_time') else '',
                    'protocol': packet.highest_layer if hasattr(packet, 'highest_layer') else 'UNKNOWN',
                    'length': packet.length if hasattr(packet, 'length') else 0
                }

                if hasattr(packet, 'ip'):
                    flow_data['src_ip'] = packet.ip.src
                    flow_data['dst_ip'] = packet.ip.dst
                    flow_key = f"{packet.ip.src}->{packet.ip.dst}"
                elif hasattr(packet, 'ipv6'):
                    flow_data['src_ip'] = packet.ipv6.src
                    flow_data['dst_ip'] = packet.ipv6.dst
                    flow_key = f"{packet.ipv6.src}->{packet.ipv6.dst}"
                else:
                    flow_data['src_ip'] = 'N/A'
                    flow_data['dst_ip'] = 'N/A'
                    flow_key = 'N/A->N/A'

                if hasattr(packet, 'tcp'):
                    flow_data['src_port'] = packet.tcp.srcport
                    flow_data['dst_port'] = packet.tcp.dstport
                elif hasattr(packet, 'udp'):
                    flow_data['src_port'] = packet.udp.srcport
                    flow_data['dst_port'] = packet.udp.dstport
                else:
                    flow_data['src_port'] = 'N/A'
                    flow_data['dst_port'] = 'N/A'

                flows.append(flow_data)
                flow_counter[flow_key] += 1
        except Exception as e:
            print(f"Warning during flow parsing: {str(e)}")
        finally:
            self.capture.close()
            self.capture = None

        return flows, dict(flow_counter.most_common(20))

    def extract_http_sessions(self) -> List[Dict[str, Any]]:
        if not self.capture:
            self.load_capture()

        http_sessions = []

        try:
            for packet in self.capture:
                if hasattr(packet, 'http'):
                    session = {
                        'timestamp': str(packet.sniff_time) if hasattr(packet, 'sniff_time') else '',
                    }

                    if hasattr(packet.http, 'host'):
                        session['host'] = packet.http.host
                    if hasattr(packet.http, 'request_method'):
                        session['method'] = packet.http.request_method
                    if hasattr(packet.http, 'request_uri'):
                        session['uri'] = packet.http.request_uri
                    if hasattr(packet.http, 'response_code'):
                        session['status_code'] = packet.http.response_code
                    if hasattr(packet.http, 'user_agent'):
                        session['user_agent'] = packet.http.user_agent

                    if session:
                        http_sessions.append(session)
        except Exception as e:
            print(f"Warning during HTTP extraction: {str(e)}")
        finally:
            self.capture.close()
            self.capture = None

        return http_sessions

    def extract_dns_queries(self) -> List[Dict[str, Any]]:
        if not self.capture:
            self.load_capture()

        dns_queries = []

        try:
            for packet in self.capture:
                if hasattr(packet, 'dns'):
                    query = {
                        'timestamp': str(packet.sniff_time) if hasattr(packet, 'sniff_time') else '',
                    }

                    if hasattr(packet.dns, 'qry_name'):
                        query['query_name'] = packet.dns.qry_name
                    if hasattr(packet.dns, 'qry_type'):
                        query['query_type'] = packet.dns.qry_type
                    if hasattr(packet.dns, 'a'):
                        query['resolved_ip'] = packet.dns.a

                    if 'query_name' in query:
                        dns_queries.append(query)
        except Exception as e:
            print(f"Warning during DNS extraction: {str(e)}")
        finally:
            self.capture.close()
            self.capture = None

        return dns_queries

    def generate_summary_json(self, output_path: str) -> Dict[str, Any]:
        stats = self.extract_basic_stats()
        flows, top_flows = self.parse_network_flows()
        http_sessions = self.extract_http_sessions()
        dns_queries = self.extract_dns_queries()

        summary = {
            'file_info': {
                'filename': Path(self.file_path).name,
                'file_hash': self.compute_file_hash()
            },
            'statistics': {
                'total_packets': stats['total_packets'],
                'top_protocols': stats['top_protocols'],
                'unique_ips_count': stats['unique_ips_count'],
                'unique_domains_count': stats['unique_domains_count']
            },
            'top_flows': top_flows,
            'http_sessions': http_sessions[:50],
            'dns_queries': dns_queries[:50],
            'unique_entities': {
                'ips': stats['unique_ips'][:100],
                'domains': stats['unique_domains'][:100]
            }
        }

        with open(output_path, 'w') as f:
            json.dump(summary, f, indent=2)

        return summary

    def generate_full_json(self, output_path: str) -> Dict[str, Any]:
        if not self.capture:
            self.load_capture()

        all_packets = []
        stats = {
            'unique_ips': set(),
            'unique_domains': set(),
            'protocols': Counter()
        }

        try:
            packet_count = 0
            for packet in self.capture:
                packet_count += 1
                packet_data = {
                    'packet_number': packet_count,
                    'timestamp': str(packet.sniff_time) if hasattr(packet, 'sniff_time') else '',
                    'length': packet.length if hasattr(packet, 'length') else 0,
                    'protocol': packet.highest_layer if hasattr(packet, 'highest_layer') else 'UNKNOWN'
                }

                stats['protocols'][packet_data['protocol']] += 1

                if hasattr(packet, 'ip'):
                    packet_data['ip'] = {
                        'src': packet.ip.src,
                        'dst': packet.ip.dst
                    }
                    stats['unique_ips'].add(packet.ip.src)
                    stats['unique_ips'].add(packet.ip.dst)
                elif hasattr(packet, 'ipv6'):
                    packet_data['ipv6'] = {
                        'src': packet.ipv6.src,
                        'dst': packet.ipv6.dst
                    }
                    stats['unique_ips'].add(packet.ipv6.src)
                    stats['unique_ips'].add(packet.ipv6.dst)

                if hasattr(packet, 'tcp'):
                    packet_data['tcp'] = {
                        'src_port': packet.tcp.srcport,
                        'dst_port': packet.tcp.dstport
                    }
                elif hasattr(packet, 'udp'):
                    packet_data['udp'] = {
                        'src_port': packet.udp.srcport,
                        'dst_port': packet.udp.dstport
                    }

                if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
                    packet_data['dns'] = {
                        'query_name': packet.dns.qry_name
                    }
                    stats['unique_domains'].add(packet.dns.qry_name)

                if hasattr(packet, 'http'):
                    packet_data['http'] = {}
                    if hasattr(packet.http, 'host'):
                        packet_data['http']['host'] = packet.http.host
                        stats['unique_domains'].add(packet.http.host)
                    if hasattr(packet.http, 'request_method'):
                        packet_data['http']['method'] = packet.http.request_method
                    if hasattr(packet.http, 'request_uri'):
                        packet_data['http']['uri'] = packet.http.request_uri

                all_packets.append(packet_data)
        except Exception as e:
            print(f"Warning during full parsing: {str(e)}")
        finally:
            self.capture.close()
            self.capture = None

        full_data = {
            'file_info': {
                'filename': Path(self.file_path).name,
                'file_hash': self.compute_file_hash()
            },
            'statistics': {
                'total_packets': len(all_packets),
                'top_protocols': dict(stats['protocols'].most_common(10)),
                'unique_ips_count': len(stats['unique_ips']),
                'unique_domains_count': len(stats['unique_domains'])
            },
            'unique_entities': {
                'ips': list(stats['unique_ips']),
                'domains': list(stats['unique_domains'])
            },
            'packets': all_packets
        }

        with open(output_path, 'w') as f:
            json.dump(full_data, f, indent=2)

        return full_data

    def get_unique_entities(self) -> Tuple[List[str], List[str]]:
        stats = self.extract_basic_stats()
        return stats['unique_ips'], stats['unique_domains']
