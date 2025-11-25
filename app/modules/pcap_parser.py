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
            'top_flows': {},
            'forensic_profile': None  # Will be populated at the end
        }

        # Lean forensic tracking for Option 1 (only essentials)
        forensic_data = {
            'first_host_seen': {},  # ip -> {mac, hostname, timestamp}
            'first_user_seen': None,  # First user account found
            'first_domain_seen': None,  # First domain found
            'os_version_seen': None,  # First OS version found
            'infected_ips': set()  # Will be populated with VT data later
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

                # Lean forensic extraction (Option 1) - only store first occurrence
                # Extract ARP for MAC address (only if not already captured)
                if hasattr(packet, 'arp'):
                    if hasattr(packet.arp, 'src_proto_ipv4') and hasattr(packet.arp, 'src_hw_mac'):
                        arp_ip = packet.arp.src_proto_ipv4
                        if arp_ip not in forensic_data['first_host_seen']:
                            forensic_data['first_host_seen'][arp_ip] = {
                                'mac': packet.arp.src_hw_mac,
                                'hostname': None,
                                'timestamp': timestamp
                            }

                # Extract DHCP for hostname (only first occurrence)
                if hasattr(packet, 'dhcp') or hasattr(packet, 'bootp'):
                    if hasattr(packet, 'bootp'):
                        dhcp_ip = packet.bootp.ip_your if hasattr(packet.bootp, 'ip_your') else None
                        dhcp_mac = packet.bootp.hw_mac_addr if hasattr(packet.bootp, 'hw_mac_addr') else None

                        if dhcp_ip and dhcp_ip != '0.0.0.0':
                            if dhcp_ip not in forensic_data['first_host_seen']:
                                forensic_data['first_host_seen'][dhcp_ip] = {
                                    'mac': dhcp_mac,
                                    'hostname': None,
                                    'timestamp': timestamp
                                }

                    if hasattr(packet, 'dhcp'):
                        # Extract hostname from DHCP Option 12
                        if hasattr(packet.dhcp, 'option_hostname') and dhcp_ip:
                            if dhcp_ip in forensic_data['first_host_seen']:
                                forensic_data['first_host_seen'][dhcp_ip]['hostname'] = packet.dhcp.option_hostname

                        # Extract domain from DHCP Option 15
                        if hasattr(packet.dhcp, 'option_domain_name') and not forensic_data['first_domain_seen']:
                            forensic_data['first_domain_seen'] = packet.dhcp.option_domain_name

                        # Extract OS fingerprint from DHCP Option 60 (Vendor Class)
                        if hasattr(packet.dhcp, 'option_vendor_class_id') and not forensic_data['os_version_seen']:
                            forensic_data['os_version_seen'] = packet.dhcp.option_vendor_class_id

                # Extract NetBIOS for hostname (only first occurrence)
                if hasattr(packet, 'nbns'):
                    if hasattr(packet.nbns, 'name') and src_ip:
                        if src_ip in forensic_data['first_host_seen']:
                            if not forensic_data['first_host_seen'][src_ip]['hostname']:
                                # Clean NetBIOS name (remove suffix like <00>)
                                nb_name = packet.nbns.name.split('<')[0] if '<' in packet.nbns.name else packet.nbns.name
                                forensic_data['first_host_seen'][src_ip]['hostname'] = nb_name
                        elif src_ip:
                            nb_name = packet.nbns.name.split('<')[0] if '<' in packet.nbns.name else packet.nbns.name
                            forensic_data['first_host_seen'][src_ip] = {
                                'mac': None,
                                'hostname': nb_name,
                                'timestamp': timestamp
                            }

                # Extract Kerberos for user account (only first occurrence)
                if hasattr(packet, 'kerberos') and not forensic_data['first_user_seen']:
                    if hasattr(packet.kerberos, 'cname_string'):
                        user = packet.kerberos.cname_string
                        realm = packet.kerberos.realm if hasattr(packet.kerberos, 'realm') else None
                        forensic_data['first_user_seen'] = f"{user}@{realm}" if realm else user
                    elif hasattr(packet.kerberos, 'cnamestring'):
                        user = packet.kerberos.cnamestring
                        realm = packet.kerberos.realm if hasattr(packet.kerberos, 'realm') else None
                        forensic_data['first_user_seen'] = f"{user}@{realm}" if realm else user

                    # Also capture realm as domain if not set
                    if hasattr(packet.kerberos, 'realm') and not forensic_data['first_domain_seen']:
                        forensic_data['first_domain_seen'] = packet.kerberos.realm

                # Extract SMB for OS version and domain (only first occurrence)
                if hasattr(packet, 'smb') or hasattr(packet, 'smb2'):
                    smb = packet.smb if hasattr(packet, 'smb') else packet.smb2

                    if hasattr(smb, 'native_os') and not forensic_data['os_version_seen']:
                        forensic_data['os_version_seen'] = smb.native_os

                    if hasattr(smb, 'domain') and not forensic_data['first_domain_seen']:
                        forensic_data['first_domain_seen'] = smb.domain

                    # Extract user from SMB if not found yet
                    if not forensic_data['first_user_seen']:
                        if hasattr(smb, 'account'):
                            forensic_data['first_user_seen'] = smb.account
                        elif hasattr(smb, 'user_name'):
                            forensic_data['first_user_seen'] = smb.user_name

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

        # Build lean forensic profile for Option 1
        def is_internal_ip(ip: str) -> bool:
            if ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.'):
                octets = ip.split('.')
                if ip.startswith('172.') and len(octets) == 4:
                    try:
                        second_octet = int(octets[1])
                        return 16 <= second_octet <= 31
                    except:
                        return False
                return True
            return False

        # Find the most likely infected host (internal IP with most traffic or first one found)
        internal_hosts = {ip: info for ip, info in forensic_data['first_host_seen'].items() if is_internal_ip(ip)}

        if internal_hosts:
            # Pick the first internal host with complete info, or just the first one
            infected_host_ip = None
            for ip, info in internal_hosts.items():
                if info.get('hostname') or info.get('mac'):
                    infected_host_ip = ip
                    break

            if not infected_host_ip:
                infected_host_ip = list(internal_hosts.keys())[0]

            host_info = internal_hosts[infected_host_ip]

            data['forensic_profile'] = {
                'infected_host': {
                    'ip': infected_host_ip,
                    'mac': host_info.get('mac', 'N/A'),
                    'hostname': host_info.get('hostname', 'N/A'),
                    'user_account': forensic_data.get('first_user_seen', 'N/A'),
                    'domain': forensic_data.get('first_domain_seen', 'N/A'),
                    'os_version': forensic_data.get('os_version_seen', 'N/A'),
                    'first_seen': host_info.get('timestamp', 'N/A')
                }
            }

            print(f"[PCAP Parser] Forensic profile created for infected host: {infected_host_ip}")
        else:
            print(f"[PCAP Parser] No internal hosts found for forensic profile")
            data['forensic_profile'] = None

        print(f"[PCAP Parser] Single-pass complete: {data['total_packets']} packets, {len(data['unique_ips'])} IPs, {len(data['unique_domains'])} domains")

        return data

    def generate_full_json(self, output_path: str, vt_results: Any = None) -> Dict[str, Any]:
        if not self.capture:
            self.load_capture()

        all_packets = []
        stats = {
            'unique_ips': set(),
            'unique_domains': set(),
            'protocols': Counter(),
            'file_hashes': set()
        }

        # Forensic tracking for aggregation
        forensic_trackers = {
            'arp_table': {},  # ip -> mac mapping
            'dhcp_info': {},  # ip -> dhcp details
            'netbios_names': {},  # ip -> netbios names
            'kerberos_users': {},  # user -> details
            'smb_sessions': {},  # ip -> smb details
            'mac_to_ip': {},  # mac -> [ips]
            'host_profiles': {}  # ip -> complete profile
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

                # Extract Ethernet/MAC layer (Layer 2)
                if hasattr(packet, 'eth'):
                    packet_data['ethernet'] = {
                        'src_mac': packet.eth.src if hasattr(packet.eth, 'src') else None,
                        'dst_mac': packet.eth.dst if hasattr(packet.eth, 'dst') else None,
                        'type': packet.eth.type if hasattr(packet.eth, 'type') else None
                    }
                    # Track MAC addresses
                    if packet_data['ethernet']['src_mac']:
                        src_mac = packet_data['ethernet']['src_mac']
                        if src_mac not in forensic_trackers['mac_to_ip']:
                            forensic_trackers['mac_to_ip'][src_mac] = []

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

                # Extract ARP packets
                if hasattr(packet, 'arp'):
                    packet_data['arp'] = {
                        'opcode': packet.arp.opcode if hasattr(packet.arp, 'opcode') else None,
                        'src_ip': packet.arp.src_proto_ipv4 if hasattr(packet.arp, 'src_proto_ipv4') else None,
                        'src_mac': packet.arp.src_hw_mac if hasattr(packet.arp, 'src_hw_mac') else None,
                        'dst_ip': packet.arp.dst_proto_ipv4 if hasattr(packet.arp, 'dst_proto_ipv4') else None,
                        'dst_mac': packet.arp.dst_hw_mac if hasattr(packet.arp, 'dst_hw_mac') else None
                    }
                    # Build ARP table
                    if packet_data['arp']['src_ip'] and packet_data['arp']['src_mac']:
                        forensic_trackers['arp_table'][packet_data['arp']['src_ip']] = {
                            'mac': packet_data['arp']['src_mac'],
                            'last_seen': packet_data['timestamp']
                        }
                    if packet_data['arp']['dst_ip'] and packet_data['arp']['dst_mac']:
                        if packet_data['arp']['dst_mac'] != '00:00:00:00:00:00':
                            forensic_trackers['arp_table'][packet_data['arp']['dst_ip']] = {
                                'mac': packet_data['arp']['dst_mac'],
                                'last_seen': packet_data['timestamp']
                            }

                # Extract DHCP/BOOTP packets
                if hasattr(packet, 'dhcp') or hasattr(packet, 'bootp'):
                    packet_data['dhcp'] = {}

                    if hasattr(packet, 'bootp'):
                        bootp = packet.bootp
                        packet_data['dhcp']['message_type'] = bootp.option_dhcp if hasattr(bootp, 'option_dhcp') else None
                        packet_data['dhcp']['client_ip'] = bootp.ip_client if hasattr(bootp, 'ip_client') else None
                        packet_data['dhcp']['your_ip'] = bootp.ip_your if hasattr(bootp, 'ip_your') else None
                        packet_data['dhcp']['server_ip'] = bootp.ip_server if hasattr(bootp, 'ip_server') else None
                        packet_data['dhcp']['client_mac'] = bootp.hw_mac_addr if hasattr(bootp, 'hw_mac_addr') else None

                    if hasattr(packet, 'dhcp'):
                        dhcp = packet.dhcp
                        # Extract DHCP options
                        packet_data['dhcp']['options'] = {}

                        # Option 12: Hostname
                        if hasattr(dhcp, 'option_hostname'):
                            packet_data['dhcp']['options']['hostname'] = dhcp.option_hostname

                        # Option 15: Domain Name
                        if hasattr(dhcp, 'option_domain_name'):
                            packet_data['dhcp']['options']['domain_name'] = dhcp.option_domain_name

                        # Option 50: Requested IP
                        if hasattr(dhcp, 'option_requested_ip_address'):
                            packet_data['dhcp']['options']['requested_ip'] = dhcp.option_requested_ip_address

                        # Option 60: Vendor Class ID
                        if hasattr(dhcp, 'option_vendor_class_id'):
                            packet_data['dhcp']['options']['vendor_class_id'] = dhcp.option_vendor_class_id

                        # Option 61: Client Identifier
                        if hasattr(dhcp, 'option_client_identifier'):
                            packet_data['dhcp']['options']['client_identifier'] = dhcp.option_client_identifier

                        # Option 81: FQDN
                        if hasattr(dhcp, 'option_fqdn'):
                            packet_data['dhcp']['options']['fqdn'] = dhcp.option_fqdn

                    # Track DHCP info for forensics
                    your_ip = packet_data['dhcp'].get('your_ip')
                    if your_ip and your_ip != '0.0.0.0':
                        if your_ip not in forensic_trackers['dhcp_info']:
                            forensic_trackers['dhcp_info'][your_ip] = {
                                'mac': packet_data['dhcp'].get('client_mac'),
                                'hostname': packet_data['dhcp'].get('options', {}).get('hostname'),
                                'domain': packet_data['dhcp'].get('options', {}).get('domain_name'),
                                'vendor': packet_data['dhcp'].get('options', {}).get('vendor_class_id'),
                                'timestamp': packet_data['timestamp']
                            }

                # Extract NetBIOS/NBNS packets
                if hasattr(packet, 'nbns'):
                    packet_data['netbios'] = {
                        'name': packet.nbns.name if hasattr(packet.nbns, 'name') else None,
                        'name_type': packet.nbns.type if hasattr(packet.nbns, 'type') else None,
                        'query_type': packet.nbns.query_type if hasattr(packet.nbns, 'query_type') else None
                    }
                    # Track NetBIOS names
                    src_ip = packet_data.get('ip', {}).get('src')
                    if src_ip and packet_data['netbios']['name']:
                        if src_ip not in forensic_trackers['netbios_names']:
                            forensic_trackers['netbios_names'][src_ip] = []
                        name_entry = {
                            'name': packet_data['netbios']['name'],
                            'type': packet_data['netbios']['name_type'],
                            'timestamp': packet_data['timestamp']
                        }
                        forensic_trackers['netbios_names'][src_ip].append(name_entry)

                # Extract NetBIOS Datagram Service
                if hasattr(packet, 'nbdgm'):
                    if not packet_data.get('netbios'):
                        packet_data['netbios'] = {}
                    packet_data['netbios']['source_name'] = packet.nbdgm.source_name if hasattr(packet.nbdgm, 'source_name') else None

                # Extract Kerberos packets
                if hasattr(packet, 'kerberos'):
                    packet_data['kerberos'] = {}
                    kerb = packet.kerberos

                    # Message type
                    if hasattr(kerb, 'msg_type'):
                        packet_data['kerberos']['message_type'] = kerb.msg_type

                    # Client name (username)
                    if hasattr(kerb, 'cname_string'):
                        packet_data['kerberos']['client_name'] = kerb.cname_string
                    elif hasattr(kerb, 'cnamestring'):
                        packet_data['kerberos']['client_name'] = kerb.cnamestring

                    # Realm (domain)
                    if hasattr(kerb, 'realm'):
                        packet_data['kerberos']['realm'] = kerb.realm

                    # Service name
                    if hasattr(kerb, 'sname_string'):
                        packet_data['kerberos']['service_name'] = kerb.sname_string
                    elif hasattr(kerb, 'snamestring'):
                        packet_data['kerberos']['service_name'] = kerb.snamestring

                    # Encryption type
                    if hasattr(kerb, 'etype'):
                        packet_data['kerberos']['encryption_type'] = kerb.etype

                    # Error code
                    if hasattr(kerb, 'error_code'):
                        packet_data['kerberos']['error_code'] = kerb.error_code

                    # Track Kerberos users
                    client_name = packet_data['kerberos'].get('client_name')
                    realm = packet_data['kerberos'].get('realm')
                    if client_name:
                        full_user = f"{client_name}@{realm}" if realm else client_name
                        if full_user not in forensic_trackers['kerberos_users']:
                            forensic_trackers['kerberos_users'][full_user] = {
                                'realm': realm,
                                'services': [],
                                'first_seen': packet_data['timestamp'],
                                'source_ip': packet_data.get('ip', {}).get('src')
                            }
                        service = packet_data['kerberos'].get('service_name')
                        if service and service not in forensic_trackers['kerberos_users'][full_user]['services']:
                            forensic_trackers['kerberos_users'][full_user]['services'].append(service)
                        forensic_trackers['kerberos_users'][full_user]['last_seen'] = packet_data['timestamp']

                # Extract SMB/SMB2 packets
                if hasattr(packet, 'smb') or hasattr(packet, 'smb2'):
                    packet_data['smb'] = {}
                    smb = packet.smb if hasattr(packet, 'smb') else packet.smb2

                    # Command
                    if hasattr(smb, 'cmd'):
                        packet_data['smb']['command'] = smb.cmd

                    # Dialect
                    if hasattr(smb, 'dialect'):
                        packet_data['smb']['dialect'] = smb.dialect

                    # Native OS
                    if hasattr(smb, 'native_os'):
                        packet_data['smb']['native_os'] = smb.native_os

                    # Native LAN Manager
                    if hasattr(smb, 'native_lan_manager'):
                        packet_data['smb']['native_lan_manager'] = smb.native_lan_manager

                    # Domain/Workgroup
                    if hasattr(smb, 'domain'):
                        packet_data['smb']['domain'] = smb.domain

                    # User name
                    if hasattr(smb, 'account'):
                        packet_data['smb']['user_name'] = smb.account
                    elif hasattr(smb, 'user_name'):
                        packet_data['smb']['user_name'] = smb.user_name

                    # Tree path (share name)
                    if hasattr(smb, 'path'):
                        packet_data['smb']['tree_path'] = smb.path

                    # File name
                    if hasattr(smb, 'file_name'):
                        packet_data['smb']['file_name'] = smb.file_name
                    elif hasattr(smb, 'filename'):
                        packet_data['smb']['file_name'] = smb.filename

                    # Track SMB sessions
                    src_ip = packet_data.get('ip', {}).get('src')
                    if src_ip:
                        if src_ip not in forensic_trackers['smb_sessions']:
                            forensic_trackers['smb_sessions'][src_ip] = {
                                'native_os': None,
                                'domain': None,
                                'users': [],
                                'shares': [],
                                'files': []
                            }

                        if packet_data['smb'].get('native_os'):
                            forensic_trackers['smb_sessions'][src_ip]['native_os'] = packet_data['smb']['native_os']
                        if packet_data['smb'].get('domain'):
                            forensic_trackers['smb_sessions'][src_ip]['domain'] = packet_data['smb']['domain']
                        if packet_data['smb'].get('user_name'):
                            user = packet_data['smb']['user_name']
                            if user not in forensic_trackers['smb_sessions'][src_ip]['users']:
                                forensic_trackers['smb_sessions'][src_ip]['users'].append(user)
                        if packet_data['smb'].get('tree_path'):
                            share = packet_data['smb']['tree_path']
                            if share not in forensic_trackers['smb_sessions'][src_ip]['shares']:
                                forensic_trackers['smb_sessions'][src_ip]['shares'].append(share)
                        if packet_data['smb'].get('file_name'):
                            file = packet_data['smb']['file_name']
                            if file not in forensic_trackers['smb_sessions'][src_ip]['files']:
                                forensic_trackers['smb_sessions'][src_ip]['files'].append(file)

                # Extract LDAP packets
                if hasattr(packet, 'ldap'):
                    packet_data['ldap'] = {}
                    ldap = packet.ldap

                    # Bind request (authentication)
                    if hasattr(ldap, 'bindrequest_name'):
                        packet_data['ldap']['bind_dn'] = ldap.bindrequest_name

                    # Search base
                    if hasattr(ldap, 'search_baseobject'):
                        packet_data['ldap']['search_base'] = ldap.search_baseobject

                    # Search filter
                    if hasattr(ldap, 'search_filter'):
                        packet_data['ldap']['search_filter'] = ldap.search_filter

                all_packets.append(packet_data)
        except Exception as e:
            print(f"Warning during full parsing: {str(e)}")
        finally:
            self.capture.close()
            self.capture = None

        file_hash = self.compute_file_hash()
        print(f"[PCAP Parser] Completed processing {len(all_packets)} packets")
        print(f"[PCAP Parser] PCAP file hash: {file_hash}")

        # Aggregate forensic metadata
        print(f"[PCAP Parser] Aggregating forensic metadata...")
        forensic_analysis = self._aggregate_forensic_metadata(all_packets, forensic_trackers, stats, vt_results)
        print(f"[PCAP Parser] Found {len(forensic_analysis['hosts'])} hosts with forensic data")
        infected_hosts = [ip for ip, host in forensic_analysis['hosts'].items() if host['is_infected']]
        if infected_hosts:
            print(f"[PCAP Parser] Identified {len(infected_hosts)} potentially infected hosts: {infected_hosts}")

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
            'forensic_analysis': forensic_analysis,
            'packets': all_packets
        }

        if len(all_packets) == 0:
            print("[PCAP Parser] WARNING: No packets were converted to JSON!")
            full_data['statistics']['conversion_complete'] = False

        with open(output_path, 'w') as f:
            json.dump(full_data, f, indent=2)

        return full_data

    def _aggregate_forensic_metadata(self, all_packets: List[Dict], forensic_trackers: Dict, stats: Dict, vt_results: Any = None) -> Dict[str, Any]:
        """Aggregate forensic metadata from all collected tracking data."""
        forensic_analysis = {
            'infected_hosts': [],  # NEW: Consolidated infected host data for easy RAG retrieval
            'hosts': {},  # All hosts detailed data
            'arp_table': {},
            'mac_vendor_lookup': {},
            'network_topology': {
                'internal_ips': [],
                'external_ips': [],
                'gateway': None,
                'dns_servers': []
            },
            'infection_timeline': []
        }

        # If forensic_trackers is empty, rebuild from packets
        if not forensic_trackers or len(forensic_trackers) == 0:
            forensic_trackers = {
                'arp_table': {},
                'dhcp_info': {},
                'netbios_names': {},
                'kerberos_users': {},
                'smb_sessions': {},
                'mac_to_ip': {},
                'host_profiles': {}
            }

            # Rebuild forensic trackers from packets
            for packet in all_packets:
                timestamp = packet.get('timestamp', '')

                # Extract ARP data
                if 'arp' in packet:
                    arp = packet['arp']
                    if arp.get('src_ip') and arp.get('src_mac'):
                        forensic_trackers['arp_table'][arp['src_ip']] = {
                            'mac': arp['src_mac'],
                            'last_seen': timestamp
                        }

                # Extract DHCP data
                if 'dhcp' in packet:
                    dhcp = packet['dhcp']
                    your_ip = dhcp.get('your_ip')
                    if your_ip and your_ip != '0.0.0.0':
                        forensic_trackers['dhcp_info'][your_ip] = {
                            'mac': dhcp.get('client_mac'),
                            'hostname': dhcp.get('options', {}).get('hostname'),
                            'domain': dhcp.get('options', {}).get('domain_name'),
                            'vendor': dhcp.get('options', {}).get('vendor_class_id'),
                            'timestamp': timestamp
                        }

                # Extract NetBIOS data
                if 'netbios' in packet:
                    nb = packet['netbios']
                    src_ip = packet.get('ip', {}).get('src')
                    if src_ip and nb.get('name'):
                        if src_ip not in forensic_trackers['netbios_names']:
                            forensic_trackers['netbios_names'][src_ip] = []
                        forensic_trackers['netbios_names'][src_ip].append({
                            'name': nb['name'],
                            'type': nb.get('name_type'),
                            'timestamp': timestamp
                        })

                # Extract Kerberos data
                if 'kerberos' in packet:
                    kerb = packet['kerberos']
                    client_name = kerb.get('client_name')
                    realm = kerb.get('realm')
                    if client_name:
                        full_user = f"{client_name}@{realm}" if realm else client_name
                        if full_user not in forensic_trackers['kerberos_users']:
                            forensic_trackers['kerberos_users'][full_user] = {
                                'realm': realm,
                                'services': [],
                                'first_seen': timestamp,
                                'source_ip': packet.get('ip', {}).get('src')
                            }
                        service = kerb.get('service_name')
                        if service and service not in forensic_trackers['kerberos_users'][full_user]['services']:
                            forensic_trackers['kerberos_users'][full_user]['services'].append(service)
                        forensic_trackers['kerberos_users'][full_user]['last_seen'] = timestamp

                # Extract SMB data
                if 'smb' in packet:
                    smb = packet['smb']
                    src_ip = packet.get('ip', {}).get('src')
                    if src_ip:
                        if src_ip not in forensic_trackers['smb_sessions']:
                            forensic_trackers['smb_sessions'][src_ip] = {
                                'native_os': None,
                                'domain': None,
                                'users': [],
                                'shares': [],
                                'files': []
                            }
                        if smb.get('native_os'):
                            forensic_trackers['smb_sessions'][src_ip]['native_os'] = smb['native_os']
                        if smb.get('domain'):
                            forensic_trackers['smb_sessions'][src_ip]['domain'] = smb['domain']
                        if smb.get('user_name') and smb['user_name'] not in forensic_trackers['smb_sessions'][src_ip]['users']:
                            forensic_trackers['smb_sessions'][src_ip]['users'].append(smb['user_name'])

        # Build ARP table
        for ip, arp_data in forensic_trackers['arp_table'].items():
            forensic_analysis['arp_table'][ip] = arp_data['mac']

        # Identify internal IPs (RFC1918)
        def is_internal_ip(ip: str) -> bool:
            if ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.'):
                octets = ip.split('.')
                if ip.startswith('172.') and len(octets) == 4:
                    second_octet = int(octets[1])
                    return 16 <= second_octet <= 31
                return True
            return False

        # Build host profiles
        for ip in stats['unique_ips']:
            if is_internal_ip(ip):
                forensic_analysis['network_topology']['internal_ips'].append(ip)
            else:
                forensic_analysis['network_topology']['external_ips'].append(ip)

            host_profile = {
                'mac_addresses': [],
                'hostnames': [],
                'netbios_names': [],
                'user_accounts': [],
                'domains': [],
                'os_versions': [],
                'first_seen': None,
                'last_seen': None,
                'total_packets': 0,
                'is_infected': False,
                'malicious_connections': []
            }

            # Get MAC address from ARP
            if ip in forensic_trackers['arp_table']:
                mac = forensic_trackers['arp_table'][ip]['mac']
                if mac not in host_profile['mac_addresses']:
                    host_profile['mac_addresses'].append(mac)

            # Get DHCP info
            if ip in forensic_trackers['dhcp_info']:
                dhcp_info = forensic_trackers['dhcp_info'][ip]
                if dhcp_info.get('hostname') and dhcp_info['hostname'] not in host_profile['hostnames']:
                    host_profile['hostnames'].append(dhcp_info['hostname'])
                if dhcp_info.get('domain') and dhcp_info['domain'] not in host_profile['domains']:
                    host_profile['domains'].append(dhcp_info['domain'])
                if dhcp_info.get('vendor') and dhcp_info['vendor'] not in host_profile['os_versions']:
                    host_profile['os_versions'].append(dhcp_info['vendor'])
                if dhcp_info.get('mac') and dhcp_info['mac'] not in host_profile['mac_addresses']:
                    host_profile['mac_addresses'].append(dhcp_info['mac'])

            # Get NetBIOS names
            if ip in forensic_trackers['netbios_names']:
                for name_entry in forensic_trackers['netbios_names'][ip]:
                    name = name_entry['name']
                    if name and name not in host_profile['netbios_names']:
                        host_profile['netbios_names'].append(name)
                    # NetBIOS name without suffix can be hostname
                    clean_name = name.split('<')[0] if '<' in name else name
                    if clean_name and clean_name not in host_profile['hostnames']:
                        host_profile['hostnames'].append(clean_name)

            # Get SMB info
            if ip in forensic_trackers['smb_sessions']:
                smb_info = forensic_trackers['smb_sessions'][ip]
                if smb_info.get('native_os') and smb_info['native_os'] not in host_profile['os_versions']:
                    host_profile['os_versions'].append(smb_info['native_os'])
                if smb_info.get('domain') and smb_info['domain'] not in host_profile['domains']:
                    host_profile['domains'].append(smb_info['domain'])
                for user in smb_info.get('users', []):
                    if user and user not in host_profile['user_accounts']:
                        host_profile['user_accounts'].append(user)

            # Get Kerberos users associated with this IP
            for user, kerb_info in forensic_trackers['kerberos_users'].items():
                if kerb_info.get('source_ip') == ip:
                    if user not in host_profile['user_accounts']:
                        host_profile['user_accounts'].append(user)
                    if kerb_info.get('realm') and kerb_info['realm'] not in host_profile['domains']:
                        host_profile['domains'].append(kerb_info['realm'])

            # Calculate timestamps and packet count
            timestamps = []
            packet_count = 0
            for packet in all_packets:
                src_ip = packet.get('ip', {}).get('src') or packet.get('ipv6', {}).get('src')
                dst_ip = packet.get('ip', {}).get('dst') or packet.get('ipv6', {}).get('dst')
                if src_ip == ip or dst_ip == ip:
                    packet_count += 1
                    if packet.get('timestamp'):
                        timestamps.append(packet['timestamp'])

            if timestamps:
                host_profile['first_seen'] = min(timestamps)
                host_profile['last_seen'] = max(timestamps)
            host_profile['total_packets'] = packet_count

            # Check if infected (has connections to malicious IPs/domains from VT)
            if vt_results and isinstance(vt_results, dict) and 'results' in vt_results:
                malicious_ips = []
                malicious_domains = []

                # Get malicious IPs from VT results
                if 'ip' in vt_results['results']:
                    for vt_ip, vt_data in vt_results['results']['ip'].items():
                        if vt_data.get('malicious', 0) > 0:
                            malicious_ips.append(vt_ip)

                # Get malicious domains from VT results
                if 'domain' in vt_results['results']:
                    for vt_domain, vt_data in vt_results['results']['domain'].items():
                        if vt_data.get('malicious', 0) > 0:
                            malicious_domains.append(vt_domain)

                # Check if this host connected to any malicious entities
                for packet in all_packets:
                    src_ip = packet.get('ip', {}).get('src')
                    dst_ip = packet.get('ip', {}).get('dst')

                    # If this is an internal host connecting to external malicious IP
                    if src_ip == ip and dst_ip in malicious_ips:
                        host_profile['is_infected'] = True
                        if dst_ip not in host_profile['malicious_connections']:
                            host_profile['malicious_connections'].append({
                                'type': 'ip',
                                'value': dst_ip,
                                'timestamp': packet.get('timestamp')
                            })

                    # Check DNS queries to malicious domains
                    if src_ip == ip and packet.get('dns', {}).get('query_name') in malicious_domains:
                        host_profile['is_infected'] = True
                        domain = packet['dns']['query_name']
                        if domain not in [c['value'] for c in host_profile['malicious_connections']]:
                            host_profile['malicious_connections'].append({
                                'type': 'domain',
                                'value': domain,
                                'timestamp': packet.get('timestamp')
                            })

            # Only add hosts with meaningful data
            if (host_profile['mac_addresses'] or host_profile['hostnames'] or
                host_profile['user_accounts'] or host_profile['total_packets'] > 10):
                forensic_analysis['hosts'][ip] = host_profile

        # Build infection timeline for infected hosts
        for ip, host in forensic_analysis['hosts'].items():
            if host['is_infected']:
                timeline_events = []

                # Add host identification events
                if host['first_seen']:
                    timeline_events.append({
                        'timestamp': host['first_seen'],
                        'description': f"Host {ip} first activity - " +
                                     (f"Hostname: {host['hostnames'][0]}" if host['hostnames'] else "Unknown host")
                    })

                # Add malicious connection events
                for conn in host['malicious_connections'][:10]:  # Limit to first 10
                    timeline_events.append({
                        'timestamp': conn['timestamp'],
                        'description': f"Malicious {conn['type']} connection: {conn['value']}"
                    })

                # Sort by timestamp
                timeline_events.sort(key=lambda x: x['timestamp'] if x['timestamp'] else '')

                forensic_analysis['infection_timeline'].extend(timeline_events)

        # Sort final timeline
        forensic_analysis['infection_timeline'].sort(key=lambda x: x['timestamp'] if x['timestamp'] else '')

        # Build consolidated infected_hosts list for easy RAG retrieval
        infected_hosts_list = []
        for ip, host in forensic_analysis['hosts'].items():
            if host['is_infected']:
                # Create consolidated infected host entry with single values (not arrays)
                infected_host = {
                    'ip': ip,
                    'mac': host['mac_addresses'][0] if host['mac_addresses'] else 'Unknown',
                    'hostname': host['hostnames'][0] if host['hostnames'] else 'Unknown',
                    'computer_name': host['hostnames'][0] if host['hostnames'] else 'Unknown',  # Synonym for RAG
                    'user_account': host['user_accounts'][0] if host['user_accounts'] else 'Unknown',
                    'domain': host['domains'][0] if host['domains'] else 'Unknown',
                    'os_info': host['os_versions'][0] if host['os_versions'] else 'Unknown',
                    'netbios_names': host['netbios_names'][:3] if host['netbios_names'] else [],  # Keep up to 3
                    'first_seen': host['first_seen'] or 'Unknown',
                    'last_seen': host['last_seen'] or 'Unknown',
                    'total_packets': host['total_packets'],
                    'is_infected': True,
                    'infection_confidence': 'high' if len(host['malicious_connections']) >= 3 else 'medium' if len(host['malicious_connections']) >= 1 else 'low',
                    'malicious_connections_count': len(host['malicious_connections']),
                    'malicious_connections': host['malicious_connections'][:5],  # First 5 connections
                    'data_sources': self._build_data_sources_map(host, forensic_trackers, ip)
                }

                # Add all known hostnames and users for completeness
                infected_host['all_hostnames'] = host['hostnames'][:5] if len(host['hostnames']) > 1 else []
                infected_host['all_users'] = host['user_accounts'][:5] if len(host['user_accounts']) > 1 else []
                infected_host['all_macs'] = host['mac_addresses'][:5] if len(host['mac_addresses']) > 1 else []

                infected_hosts_list.append(infected_host)

        # Sort by infection confidence and connection count
        infected_hosts_list.sort(key=lambda x: (x['infection_confidence'] == 'high', x['malicious_connections_count']), reverse=True)
        forensic_analysis['infected_hosts'] = infected_hosts_list

        print(f"[Forensic Analysis] Identified {len(infected_hosts_list)} infected hosts")
        for infected in infected_hosts_list:
            print(f"  - {infected['ip']} (hostname: {infected['hostname']}, MAC: {infected['mac']}, confidence: {infected['infection_confidence']})")

        return forensic_analysis

    def _build_data_sources_map(self, host_profile: Dict[str, Any], forensic_trackers: Dict, ip: str) -> Dict[str, str]:
        """Build a map of where each piece of forensic data came from."""
        sources = {}

        # Track MAC address source
        if host_profile['mac_addresses']:
            if ip in forensic_trackers.get('arp_table', {}):
                sources['mac'] = 'ARP table'
            elif ip in forensic_trackers.get('dhcp_info', {}):
                sources['mac'] = 'DHCP'
            else:
                sources['mac'] = 'Ethernet layer'

        # Track hostname source
        if host_profile['hostnames']:
            hostname = host_profile['hostnames'][0]
            if ip in forensic_trackers.get('dhcp_info', {}) and forensic_trackers['dhcp_info'][ip].get('hostname') == hostname:
                sources['hostname'] = 'DHCP Option 12'
            elif ip in forensic_trackers.get('netbios_names', {}):
                sources['hostname'] = 'NetBIOS/NBNS'
            else:
                sources['hostname'] = 'SMB'

        # Track user account source
        if host_profile['user_accounts']:
            user = host_profile['user_accounts'][0]
            # Check if from Kerberos
            from_kerberos = False
            for kerb_user, kerb_info in forensic_trackers.get('kerberos_users', {}).items():
                if kerb_info.get('source_ip') == ip and kerb_user.startswith(user.split('@')[0]):
                    sources['user_account'] = 'Kerberos authentication'
                    from_kerberos = True
                    break
            if not from_kerberos:
                sources['user_account'] = 'SMB session'

        # Track domain source
        if host_profile['domains']:
            domain = host_profile['domains'][0]
            if ip in forensic_trackers.get('dhcp_info', {}) and forensic_trackers['dhcp_info'][ip].get('domain') == domain:
                sources['domain'] = 'DHCP Option 15'
            else:
                # Check Kerberos
                from_kerberos = False
                for kerb_user, kerb_info in forensic_trackers.get('kerberos_users', {}).items():
                    if kerb_info.get('source_ip') == ip and kerb_info.get('realm') == domain:
                        sources['domain'] = 'Kerberos realm'
                        from_kerberos = True
                        break
                if not from_kerberos:
                    sources['domain'] = 'SMB domain'

        # Track OS info source
        if host_profile['os_versions']:
            sources['os_info'] = 'SMB native_os' if ip in forensic_trackers.get('smb_sessions', {}) else 'DHCP Vendor Class'

        return sources

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
