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

    def parse_network_flows(self) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        if not self.capture:
            self.load_capture()

        flows = []
        flow_counter = Counter()
        flow_metadata = {}

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
                    src_port = getattr(packet.tcp, 'srcport', None) if hasattr(packet, 'tcp') else getattr(packet.udp, 'srcport', None) if hasattr(packet, 'udp') else 'N/A'
                    dst_port = getattr(packet.tcp, 'dstport', None) if hasattr(packet, 'tcp') else getattr(packet.udp, 'dstport', None) if hasattr(packet, 'udp') else 'N/A'
                    flow_key = f"{packet.ip.src}:{src_port}->{packet.ip.dst}:{dst_port}"
                elif hasattr(packet, 'ipv6'):
                    flow_data['src_ip'] = packet.ipv6.src
                    flow_data['dst_ip'] = packet.ipv6.dst
                    src_port = getattr(packet.tcp, 'srcport', None) if hasattr(packet, 'tcp') else getattr(packet.udp, 'srcport', None) if hasattr(packet, 'udp') else 'N/A'
                    dst_port = getattr(packet.tcp, 'dstport', None) if hasattr(packet, 'tcp') else getattr(packet.udp, 'dstport', None) if hasattr(packet, 'udp') else 'N/A'
                    flow_key = f"{packet.ipv6.src}:{src_port}->{packet.ipv6.dst}:{dst_port}"
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

                if flow_key not in flow_metadata:
                    flow_metadata[flow_key] = {
                        'first_seen': flow_data['timestamp'],
                        'last_seen': flow_data['timestamp'],
                        'total_bytes': 0,
                        'packet_count': 0,
                        'protocol': flow_data['protocol']
                    }

                flow_metadata[flow_key]['last_seen'] = flow_data['timestamp']
                flow_metadata[flow_key]['total_bytes'] += int(flow_data['length'])
                flow_metadata[flow_key]['packet_count'] += 1

        except Exception as e:
            print(f"Warning during flow parsing: {str(e)}")
        finally:
            self.capture.close()
            self.capture = None

        top_flows_with_metadata = {}
        for flow_key, count in flow_counter.most_common(20):
            if flow_key in flow_metadata:
                metadata = flow_metadata[flow_key]
                top_flows_with_metadata[flow_key] = {
                    'packet_count': count,
                    'first_seen': metadata['first_seen'],
                    'last_seen': metadata['last_seen'],
                    'total_bytes': metadata['total_bytes'],
                    'protocol': metadata['protocol']
                }

        return flows, top_flows_with_metadata

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
                        if hasattr(packet.http, 'host'):
                            session['full_url'] = f"{packet.http.host}{packet.http.request_uri}"
                    if hasattr(packet.http, 'response_code'):
                        session['status_code'] = packet.http.response_code
                    if hasattr(packet.http, 'user_agent'):
                        session['user_agent'] = packet.http.user_agent
                    if hasattr(packet.http, 'content_type'):
                        session['content_type'] = packet.http.content_type
                    if hasattr(packet.http, 'content_length'):
                        session['content_length'] = packet.http.content_length
                    if hasattr(packet.http, 'referer'):
                        session['referer'] = packet.http.referer

                    if hasattr(packet, 'ip'):
                        session['src_ip'] = packet.ip.src
                        session['dst_ip'] = packet.ip.dst

                    if hasattr(packet, 'tcp'):
                        session['src_port'] = packet.tcp.srcport
                        session['dst_port'] = packet.tcp.dstport

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
                    if hasattr(packet.dns, 'qry_class'):
                        query['query_class'] = packet.dns.qry_class

                    if hasattr(packet.dns, 'flags_response'):
                        query['is_response'] = packet.dns.flags_response == '1'

                    if hasattr(packet.dns, 'a'):
                        query['resolved_ip'] = packet.dns.a
                    elif hasattr(packet.dns, 'aaaa'):
                        query['resolved_ipv6'] = packet.dns.aaaa
                    elif hasattr(packet.dns, 'cname'):
                        query['cname'] = packet.dns.cname

                    if hasattr(packet.dns, 'resp_name'):
                        query['response_name'] = packet.dns.resp_name

                    if hasattr(packet, 'ip'):
                        query['src_ip'] = packet.ip.src
                        query['dst_ip'] = packet.ip.dst

                    if 'query_name' in query:
                        dns_queries.append(query)
        except Exception as e:
            print(f"Warning during DNS extraction: {str(e)}")
        finally:
            self.capture.close()
            self.capture = None

        return dns_queries

    def extract_connection_metadata(self) -> List[Dict[str, Any]]:
        if not self.capture:
            self.load_capture()

        connections = []
        connection_tracker = {}

        try:
            for packet in self.capture:
                if hasattr(packet, 'tcp'):
                    timestamp = str(packet.sniff_time) if hasattr(packet, 'sniff_time') else ''

                    if hasattr(packet, 'ip'):
                        src_ip = packet.ip.src
                        dst_ip = packet.ip.dst
                    elif hasattr(packet, 'ipv6'):
                        src_ip = packet.ipv6.src
                        dst_ip = packet.ipv6.dst
                    else:
                        continue

                    src_port = packet.tcp.srcport
                    dst_port = packet.tcp.dstport
                    conn_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"

                    flags = packet.tcp.flags if hasattr(packet.tcp, 'flags') else None

                    if conn_key not in connection_tracker:
                        connection_tracker[conn_key] = {
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'first_seen': timestamp,
                            'last_seen': timestamp,
                            'syn_timestamp': None,
                            'syn_ack_timestamp': None,
                            'established_timestamp': None,
                            'fin_timestamp': None,
                            'rst_timestamp': None,
                            'flags_observed': set(),
                            'state': 'UNKNOWN'
                        }

                    conn = connection_tracker[conn_key]
                    conn['last_seen'] = timestamp

                    if flags:
                        conn['flags_observed'].add(str(flags))

                        if 'SYN' in str(flags) and 'ACK' not in str(flags):
                            conn['syn_timestamp'] = timestamp
                            conn['state'] = 'SYN_SENT'
                        elif 'SYN' in str(flags) and 'ACK' in str(flags):
                            conn['syn_ack_timestamp'] = timestamp
                            conn['state'] = 'SYN_ACK'
                        elif 'ACK' in str(flags) and conn['state'] in ['SYN_ACK', 'SYN_SENT']:
                            conn['established_timestamp'] = timestamp
                            conn['state'] = 'ESTABLISHED'
                        elif 'FIN' in str(flags):
                            conn['fin_timestamp'] = timestamp
                            conn['state'] = 'FIN_WAIT'
                        elif 'RST' in str(flags):
                            conn['rst_timestamp'] = timestamp
                            conn['state'] = 'RESET'

        except Exception as e:
            print(f"Warning during connection metadata extraction: {str(e)}")
        finally:
            self.capture.close()
            self.capture = None

        for conn_key, conn_data in connection_tracker.items():
            conn_data['flags_observed'] = list(conn_data['flags_observed'])
            connections.append(conn_data)

        connections.sort(key=lambda x: x['first_seen'])
        return connections[:50]

    def extract_file_transfer_indicators(self) -> List[Dict[str, Any]]:
        if not self.capture:
            self.load_capture()

        file_transfers = []

        try:
            for packet in self.capture:
                if hasattr(packet, 'http'):
                    timestamp = str(packet.sniff_time) if hasattr(packet, 'sniff_time') else ''

                    transfer = None

                    if hasattr(packet.http, 'request_method') and packet.http.request_method in ['GET', 'POST', 'PUT']:
                        transfer = {
                            'timestamp': timestamp,
                            'direction': 'download' if packet.http.request_method == 'GET' else 'upload',
                            'method': packet.http.request_method
                        }

                        if hasattr(packet.http, 'host'):
                            transfer['host'] = packet.http.host
                        if hasattr(packet.http, 'request_uri'):
                            transfer['uri'] = packet.http.request_uri
                            if hasattr(packet.http, 'host'):
                                transfer['url'] = f"{packet.http.host}{packet.http.request_uri}"

                        if hasattr(packet, 'ip'):
                            transfer['src_ip'] = packet.ip.src
                            transfer['dst_ip'] = packet.ip.dst

                    if hasattr(packet.http, 'content_type'):
                        if not transfer:
                            transfer = {'timestamp': timestamp}
                        transfer['content_type'] = packet.http.content_type
                        transfer['file_mime_type'] = packet.http.content_type

                    if hasattr(packet.http, 'content_length'):
                        if not transfer:
                            transfer = {'timestamp': timestamp}
                        try:
                            transfer['file_size'] = int(packet.http.content_length)
                        except:
                            transfer['file_size'] = packet.http.content_length

                    if hasattr(packet.http, 'response_code'):
                        if transfer:
                            transfer['response_code'] = packet.http.response_code

                    if hasattr(packet.http, 'content_disposition'):
                        if not transfer:
                            transfer = {'timestamp': timestamp}
                        transfer['content_disposition'] = packet.http.content_disposition
                        if 'filename' in str(packet.http.content_disposition).lower():
                            transfer['file_downloaded'] = True

                    if transfer and ('content_type' in transfer or 'file_size' in transfer or 'content_disposition' in transfer):
                        if 'direction' not in transfer:
                            transfer['direction'] = 'unknown'
                        file_transfers.append(transfer)

        except Exception as e:
            print(f"Warning during file transfer extraction: {str(e)}")
        finally:
            self.capture.close()
            self.capture = None

        return file_transfers[:50]

    def generate_summary_json(self, output_path: str) -> Dict[str, Any]:
        """Generate summary using optimized single-pass extraction with caching."""
        file_hash = self.compute_file_hash()
        cache_dir = Path(output_path).parent / 'cache'
        cache_dir.mkdir(exist_ok=True)
        cache_file = cache_dir / f"{file_hash}_summary.json"

        if cache_file.exists():
            print(f"[PCAP Parser] Cache hit! Loading cached summary for {file_hash[:16]}...")
            try:
                with open(cache_file, 'r') as f:
                    cached_summary = json.load(f)
                    cached_summary['file_info']['filename'] = Path(self.file_path).name

                    with open(output_path, 'w') as out_f:
                        json.dump(cached_summary, out_f, indent=2)

                    print(f"[PCAP Parser] Loaded from cache: {cached_summary['statistics']['total_packets']} packets")
                    return cached_summary
            except Exception as e:
                print(f"[PCAP Parser] Cache read failed: {str(e)}, re-parsing...")

        print("[PCAP Parser] Starting optimized single-pass extraction...")
        all_data = self._single_pass_extract()

        summary = {
            'file_info': {
                'filename': Path(self.file_path).name,
                'file_hash': file_hash
            },
            'statistics': {
                'total_packets': all_data['total_packets'],
                'top_protocols': dict(all_data['protocols'].most_common(10)),
                'unique_ips_count': len(all_data['unique_ips']),
                'unique_domains_count': len(all_data['unique_domains'])
            },
            'top_flows': all_data['top_flows'],
            'http_sessions': all_data['http_sessions'][:50],
            'dns_queries': all_data['dns_queries'][:50],
            'tcp_connections': all_data['tcp_connections'][:50],
            'file_transfers': all_data['file_transfers'][:50],
            'unique_entities': {
                'ips': list(all_data['unique_ips'])[:100],
                'domains': list(all_data['unique_domains'])[:100]
            }
        }

        with open(output_path, 'w') as f:
            json.dump(summary, f, indent=2)

        try:
            with open(cache_file, 'w') as f:
                json.dump(summary, f, indent=2)
            print(f"[PCAP Parser] Summary cached at: {cache_file}")
        except Exception as e:
            print(f"[PCAP Parser] Warning: Failed to cache summary: {str(e)}")

        print(f"[PCAP Parser] Summary generated: {all_data['total_packets']} packets processed")
        return summary

    def _single_pass_extract(self) -> Dict[str, Any]:
        """Extract all needed data in a single pass through the PCAP file."""
        if not self.capture:
            self.load_capture()

        data = {
            'total_packets': 0,
            'protocols': Counter(),
            'unique_ips': set(),
            'unique_domains': set(),
            'flow_counter': Counter(),
            'flow_metadata': {},
            'http_sessions': [],
            'dns_queries': [],
            'tcp_connections': [],
            'connection_tracker': {},
            'file_transfers': [],
            'top_flows': {}
        }

        try:
            for packet in self.capture:
                data['total_packets'] += 1

                if data['total_packets'] % 500 == 0:
                    print(f"[PCAP Parser] Processed {data['total_packets']} packets...")

                timestamp = str(packet.sniff_time) if hasattr(packet, 'sniff_time') else ''
                protocol = packet.highest_layer if hasattr(packet, 'highest_layer') else 'UNKNOWN'
                packet_length = int(packet.length) if hasattr(packet, 'length') else 0

                data['protocols'][protocol] += 1

                src_ip, dst_ip = None, None
                if hasattr(packet, 'ip'):
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    data['unique_ips'].add(src_ip)
                    data['unique_ips'].add(dst_ip)
                elif hasattr(packet, 'ipv6'):
                    src_ip = packet.ipv6.src
                    dst_ip = packet.ipv6.dst
                    data['unique_ips'].add(src_ip)
                    data['unique_ips'].add(dst_ip)

                src_port, dst_port = None, None
                if hasattr(packet, 'tcp'):
                    src_port = packet.tcp.srcport
                    dst_port = packet.tcp.dstport

                    if src_ip and dst_ip:
                        conn_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
                        flags = packet.tcp.flags if hasattr(packet.tcp, 'flags') else None

                        if conn_key not in data['connection_tracker']:
                            data['connection_tracker'][conn_key] = {
                                'src_ip': src_ip,
                                'dst_ip': dst_ip,
                                'src_port': src_port,
                                'dst_port': dst_port,
                                'first_seen': timestamp,
                                'last_seen': timestamp,
                                'state': 'UNKNOWN',
                                'established_timestamp': None
                            }

                        conn = data['connection_tracker'][conn_key]
                        conn['last_seen'] = timestamp

                        if flags:
                            if 'SYN' in str(flags) and 'ACK' not in str(flags):
                                conn['state'] = 'SYN_SENT'
                            elif 'SYN' in str(flags) and 'ACK' in str(flags):
                                conn['state'] = 'SYN_ACK'
                            elif 'ACK' in str(flags) and conn['state'] in ['SYN_ACK', 'SYN_SENT']:
                                conn['established_timestamp'] = timestamp
                                conn['state'] = 'ESTABLISHED'
                            elif 'FIN' in str(flags):
                                conn['state'] = 'FIN_WAIT'
                            elif 'RST' in str(flags):
                                conn['state'] = 'RESET'

                elif hasattr(packet, 'udp'):
                    src_port = packet.udp.srcport
                    dst_port = packet.udp.dstport

                if src_ip and dst_ip and src_port and dst_port:
                    flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
                    data['flow_counter'][flow_key] += 1

                    if flow_key not in data['flow_metadata']:
                        data['flow_metadata'][flow_key] = {
                            'first_seen': timestamp,
                            'last_seen': timestamp,
                            'total_bytes': 0,
                            'packet_count': 0,
                            'protocol': protocol
                        }

                    data['flow_metadata'][flow_key]['last_seen'] = timestamp
                    data['flow_metadata'][flow_key]['total_bytes'] += packet_length
                    data['flow_metadata'][flow_key]['packet_count'] += 1

                if hasattr(packet, 'http'):
                    session = {'timestamp': timestamp}

                    if hasattr(packet.http, 'host'):
                        session['host'] = packet.http.host
                        data['unique_domains'].add(packet.http.host)
                    if hasattr(packet.http, 'request_method'):
                        session['method'] = packet.http.request_method
                    if hasattr(packet.http, 'request_uri'):
                        session['uri'] = packet.http.request_uri
                        if hasattr(packet.http, 'host'):
                            session['full_url'] = f"{packet.http.host}{packet.http.request_uri}"
                    if hasattr(packet.http, 'response_code'):
                        session['status_code'] = packet.http.response_code
                    if hasattr(packet.http, 'content_type'):
                        session['content_type'] = packet.http.content_type
                    if hasattr(packet.http, 'content_length'):
                        session['content_length'] = packet.http.content_length

                    if src_ip:
                        session['src_ip'] = src_ip
                    if dst_ip:
                        session['dst_ip'] = dst_ip
                    if src_port:
                        session['src_port'] = src_port
                    if dst_port:
                        session['dst_port'] = dst_port

                    if session:
                        data['http_sessions'].append(session)

                    if hasattr(packet.http, 'request_method') and packet.http.request_method in ['GET', 'POST', 'PUT']:
                        transfer = {
                            'timestamp': timestamp,
                            'direction': 'download' if packet.http.request_method == 'GET' else 'upload',
                            'method': packet.http.request_method
                        }

                        if hasattr(packet.http, 'host'):
                            transfer['host'] = packet.http.host
                        if hasattr(packet.http, 'request_uri'):
                            transfer['uri'] = packet.http.request_uri
                            if hasattr(packet.http, 'host'):
                                transfer['url'] = f"{packet.http.host}{packet.http.request_uri}"
                        if hasattr(packet.http, 'content_type'):
                            transfer['content_type'] = packet.http.content_type
                        if hasattr(packet.http, 'content_length'):
                            try:
                                transfer['file_size'] = int(packet.http.content_length)
                            except:
                                transfer['file_size'] = packet.http.content_length

                        if src_ip:
                            transfer['src_ip'] = src_ip
                        if dst_ip:
                            transfer['dst_ip'] = dst_ip

                        if 'content_type' in transfer or 'file_size' in transfer:
                            data['file_transfers'].append(transfer)

                if hasattr(packet, 'dns'):
                    query = {'timestamp': timestamp}

                    if hasattr(packet.dns, 'qry_name'):
                        query['query_name'] = packet.dns.qry_name
                        data['unique_domains'].add(packet.dns.qry_name)
                    if hasattr(packet.dns, 'qry_type'):
                        query['query_type'] = packet.dns.qry_type
                    if hasattr(packet.dns, 'flags_response'):
                        query['is_response'] = packet.dns.flags_response == '1'
                    if hasattr(packet.dns, 'a'):
                        query['resolved_ip'] = packet.dns.a

                    if src_ip:
                        query['src_ip'] = src_ip
                    if dst_ip:
                        query['dst_ip'] = dst_ip

                    if 'query_name' in query:
                        data['dns_queries'].append(query)

        except Exception as e:
            print(f"[PCAP Parser] Warning during single-pass extraction: {str(e)}")
        finally:
            self.capture.close()
            self.capture = None

        for flow_key, count in data['flow_counter'].most_common(20):
            if flow_key in data['flow_metadata']:
                metadata = data['flow_metadata'][flow_key]
                data['top_flows'][flow_key] = {
                    'packet_count': count,
                    'first_seen': metadata['first_seen'],
                    'last_seen': metadata['last_seen'],
                    'total_bytes': metadata['total_bytes'],
                    'protocol': metadata['protocol']
                }

        data['tcp_connections'] = list(data['connection_tracker'].values())
        data['tcp_connections'].sort(key=lambda x: x['first_seen'])

        print(f"[PCAP Parser] Single-pass complete: {data['total_packets']} packets, {len(data['unique_ips'])} IPs, {len(data['unique_domains'])} domains")

        return data

    def generate_full_json(self, output_path: str) -> Dict[str, Any]:
        if not self.capture:
            self.load_capture()

        all_packets = []
        stats = {
            'unique_ips': set(),
            'unique_domains': set(),
            'protocols': Counter(),
            'file_hashes': set()
        }

        try:
            packet_count = 0
            print(f"[PCAP Parser] Starting full JSON conversion...")
            for packet in self.capture:
                packet_count += 1
                if packet_count % 100 == 0:
                    print(f"[PCAP Parser] Processed {packet_count} packets...")

                packet_data = {
                    'packet_number': packet_count,
                    'timestamp': str(packet.sniff_time) if hasattr(packet, 'sniff_time') else '',
                    'length': packet.length if hasattr(packet, 'length') else 0,
                    'protocol': packet.highest_layer if hasattr(packet, 'highest_layer') else 'UNKNOWN',
                    'layers': []
                }

                for layer in packet.layers:
                    packet_data['layers'].append(layer.layer_name)

                stats['protocols'][packet_data['protocol']] += 1

                if hasattr(packet, 'ip'):
                    packet_data['ip'] = {
                        'src': packet.ip.src,
                        'dst': packet.ip.dst,
                        'version': packet.ip.version if hasattr(packet.ip, 'version') else None,
                        'ttl': packet.ip.ttl if hasattr(packet.ip, 'ttl') else None,
                        'protocol': packet.ip.proto if hasattr(packet.ip, 'proto') else None
                    }
                    stats['unique_ips'].add(packet.ip.src)
                    stats['unique_ips'].add(packet.ip.dst)
                elif hasattr(packet, 'ipv6'):
                    packet_data['ipv6'] = {
                        'src': packet.ipv6.src,
                        'dst': packet.ipv6.dst,
                        'version': '6',
                        'hop_limit': packet.ipv6.hlim if hasattr(packet.ipv6, 'hlim') else None
                    }
                    stats['unique_ips'].add(packet.ipv6.src)
                    stats['unique_ips'].add(packet.ipv6.dst)

                if hasattr(packet, 'tcp'):
                    packet_data['tcp'] = {
                        'src_port': packet.tcp.srcport,
                        'dst_port': packet.tcp.dstport,
                        'flags': packet.tcp.flags if hasattr(packet.tcp, 'flags') else None,
                        'seq': packet.tcp.seq if hasattr(packet.tcp, 'seq') else None,
                        'ack': packet.tcp.ack if hasattr(packet.tcp, 'ack') else None,
                        'window_size': packet.tcp.window_size if hasattr(packet.tcp, 'window_size') else None
                    }
                elif hasattr(packet, 'udp'):
                    packet_data['udp'] = {
                        'src_port': packet.udp.srcport,
                        'dst_port': packet.udp.dstport,
                        'length': packet.udp.length if hasattr(packet.udp, 'length') else None
                    }

                if hasattr(packet, 'icmp'):
                    packet_data['icmp'] = {
                        'type': packet.icmp.type if hasattr(packet.icmp, 'type') else None,
                        'code': packet.icmp.code if hasattr(packet.icmp, 'code') else None
                    }

                if hasattr(packet, 'dns'):
                    packet_data['dns'] = {}
                    if hasattr(packet.dns, 'qry_name'):
                        packet_data['dns']['query_name'] = packet.dns.qry_name
                        stats['unique_domains'].add(packet.dns.qry_name)
                    if hasattr(packet.dns, 'qry_type'):
                        packet_data['dns']['query_type'] = packet.dns.qry_type
                    if hasattr(packet.dns, 'flags'):
                        packet_data['dns']['flags'] = packet.dns.flags
                    if hasattr(packet.dns, 'a'):
                        packet_data['dns']['answer'] = packet.dns.a

                if hasattr(packet, 'http'):
                    packet_data['http'] = {}
                    if hasattr(packet.http, 'host'):
                        packet_data['http']['host'] = packet.http.host
                        stats['unique_domains'].add(packet.http.host)
                    if hasattr(packet.http, 'request_method'):
                        packet_data['http']['method'] = packet.http.request_method
                    if hasattr(packet.http, 'request_uri'):
                        packet_data['http']['uri'] = packet.http.request_uri
                    if hasattr(packet.http, 'response_code'):
                        packet_data['http']['status_code'] = packet.http.response_code
                    if hasattr(packet.http, 'user_agent'):
                        packet_data['http']['user_agent'] = packet.http.user_agent
                    if hasattr(packet.http, 'content_type'):
                        packet_data['http']['content_type'] = packet.http.content_type

                if hasattr(packet, 'tls'):
                    packet_data['tls'] = {}
                    if hasattr(packet.tls, 'handshake_type'):
                        packet_data['tls']['handshake_type'] = packet.tls.handshake_type
                    if hasattr(packet.tls, 'record_version'):
                        packet_data['tls']['version'] = packet.tls.record_version

                if hasattr(packet, 'data'):
                    try:
                        data_layer = packet.data
                        if hasattr(data_layer, 'data'):
                            data_hex = data_layer.data
                            if len(data_hex) > 0:
                                packet_data['has_payload'] = True
                                packet_data['payload_length'] = len(data_hex) // 2
                    except:
                        pass

                all_packets.append(packet_data)
        except Exception as e:
            print(f"Warning during full parsing: {str(e)}")
        finally:
            self.capture.close()
            self.capture = None

        file_hash = self.compute_file_hash()
        print(f"[PCAP Parser] Completed processing {len(all_packets)} packets")
        print(f"[PCAP Parser] PCAP file hash: {file_hash}")

        full_data = {
            'file_info': {
                'filename': Path(self.file_path).name,
                'file_hash': file_hash,
                'total_size_bytes': Path(self.file_path).stat().st_size
            },
            'statistics': {
                'total_packets': len(all_packets),
                'top_protocols': dict(stats['protocols'].most_common(10)),
                'unique_ips_count': len(stats['unique_ips']),
                'unique_domains_count': len(stats['unique_domains']),
                'conversion_complete': True
            },
            'unique_entities': {
                'ips': list(stats['unique_ips']),
                'domains': list(stats['unique_domains'])
            },
            'packets': all_packets
        }

        if len(all_packets) == 0:
            print("[PCAP Parser] WARNING: No packets were converted to JSON!")
            full_data['statistics']['conversion_complete'] = False

        with open(output_path, 'w') as f:
            json.dump(full_data, f, indent=2)

        return full_data

    def get_unique_entities(self) -> Tuple[List[str], List[str]]:
        stats = self.extract_basic_stats()
        return stats['unique_ips'], stats['unique_domains']

    def get_prioritized_entities(self, max_ips: int = 5, max_domains: int = 5) -> Dict[str, List[str]]:
        if not self.capture:
            self.load_capture()

        ip_scores = {}
        domain_scores = {}
        http_hosts = set()
        http_ips = set()
        tcp_established = {}

        try:
            for packet in self.capture:
                if hasattr(packet, 'ip'):
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst

                    if src_ip not in ip_scores:
                        ip_scores[src_ip] = {'packet_count': 0, 'bytes': 0, 'http': False, 'tcp_established': False}
                    if dst_ip not in ip_scores:
                        ip_scores[dst_ip] = {'packet_count': 0, 'bytes': 0, 'http': False, 'tcp_established': False}

                    packet_length = int(packet.length) if hasattr(packet, 'length') else 0
                    ip_scores[src_ip]['packet_count'] += 1
                    ip_scores[src_ip]['bytes'] += packet_length
                    ip_scores[dst_ip]['packet_count'] += 1
                    ip_scores[dst_ip]['bytes'] += packet_length

                elif hasattr(packet, 'ipv6'):
                    src_ip = packet.ipv6.src
                    dst_ip = packet.ipv6.dst

                    if src_ip not in ip_scores:
                        ip_scores[src_ip] = {'packet_count': 0, 'bytes': 0, 'http': False, 'tcp_established': False}
                    if dst_ip not in ip_scores:
                        ip_scores[dst_ip] = {'packet_count': 0, 'bytes': 0, 'http': False, 'tcp_established': False}

                    packet_length = int(packet.length) if hasattr(packet, 'length') else 0
                    ip_scores[src_ip]['packet_count'] += 1
                    ip_scores[src_ip]['bytes'] += packet_length
                    ip_scores[dst_ip]['packet_count'] += 1
                    ip_scores[dst_ip]['bytes'] += packet_length

                if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags'):
                    flags = packet.tcp.flags
                    if hasattr(packet, 'ip'):
                        flow_key = f"{packet.ip.src}:{packet.tcp.srcport}->{packet.ip.dst}:{packet.tcp.dstport}"
                        if 'SYN' in str(flags) and 'ACK' in str(flags):
                            tcp_established[flow_key] = True
                            ip_scores[packet.ip.src]['tcp_established'] = True
                            ip_scores[packet.ip.dst]['tcp_established'] = True

                if hasattr(packet, 'http'):
                    if hasattr(packet.http, 'host'):
                        host = packet.http.host
                        http_hosts.add(host)

                        if host not in domain_scores:
                            domain_scores[host] = {'request_count': 0, 'bytes': 0, 'http': True}
                        domain_scores[host]['request_count'] += 1

                        if hasattr(packet, 'ip'):
                            http_ips.add(packet.ip.dst)
                            if packet.ip.dst in ip_scores:
                                ip_scores[packet.ip.dst]['http'] = True
                            if packet.ip.src in ip_scores:
                                ip_scores[packet.ip.src]['http'] = True

                if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
                    domain = packet.dns.qry_name
                    if domain not in domain_scores:
                        domain_scores[domain] = {'request_count': 0, 'bytes': 0, 'http': False}
                    domain_scores[domain]['request_count'] += 1

        except Exception as e:
            print(f"Warning during prioritization: {str(e)}")
        finally:
            self.capture.close()
            self.capture = None

        def calculate_ip_priority(ip: str, stats: Dict) -> float:
            score = 0.0
            score += stats['packet_count'] * 1.0
            score += (stats['bytes'] / 1000) * 2.0
            if stats['http']:
                score += 500.0
            if stats['tcp_established']:
                score += 200.0
            return score

        def calculate_domain_priority(domain: str, stats: Dict) -> float:
            score = 0.0
            score += stats['request_count'] * 10.0
            if stats['http']:
                score += 300.0
            return score

        ip_priority_list = [
            (ip, calculate_ip_priority(ip, stats))
            for ip, stats in ip_scores.items()
        ]
        ip_priority_list.sort(key=lambda x: x[1], reverse=True)

        domain_priority_list = [
            (domain, calculate_domain_priority(domain, stats))
            for domain, stats in domain_scores.items()
        ]
        domain_priority_list.sort(key=lambda x: x[1], reverse=True)

        prioritized_ips = [ip for ip, score in ip_priority_list[:max_ips]]
        prioritized_domains = [domain for domain, score in domain_priority_list[:max_domains]]

        print(f"[PCAP Parser] Prioritized {len(prioritized_ips)} IPs and {len(prioritized_domains)} domains for VirusTotal queries")
        print(f"[PCAP Parser] Top IPs: {prioritized_ips}")
        print(f"[PCAP Parser] Top domains: {prioritized_domains}")

        return {
            'ips': prioritized_ips,
            'domains': prioritized_domains,
            'http_hosts': list(http_hosts),
            'http_ips': list(http_ips),
            'total_ips_found': len(ip_scores),
            'total_domains_found': len(domain_scores)
        }
