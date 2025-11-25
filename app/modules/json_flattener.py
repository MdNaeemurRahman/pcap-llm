from typing import Dict, Any, List


class JSONFlattener:
    @staticmethod
    def flatten_infected_host(infected_host: Dict[str, Any]) -> str:
        text_parts = []

        text_parts.append("=== INFECTED HOST FORENSIC DATA ===\n")
        text_parts.append("This section contains identification details for a compromised system.\n")

        ip = infected_host.get('ip', 'Unknown')
        mac = infected_host.get('mac', 'Unknown')
        hostname = infected_host.get('hostname', 'Unknown')
        user = infected_host.get('user_account', 'Unknown')
        domain = infected_host.get('domain', 'Unknown')
        os_info = infected_host.get('os_info', 'Unknown')

        text_parts.append("## Host Identification Table\n")
        text_parts.append(f"Field: ip_address | Value: {ip}")
        if infected_host.get('data_sources', {}).get('ip'):
            text_parts.append(f" | Source: {infected_host['data_sources']['ip']}")
        text_parts.append("\n")

        if hostname != 'Unknown':
            text_parts.append(f"Field: hostname | Value: {hostname}")
            if infected_host.get('data_sources', {}).get('hostname'):
                text_parts.append(f" | Source: {infected_host['data_sources']['hostname']}")
            text_parts.append("\n")

        if mac != 'Unknown':
            text_parts.append(f"Field: mac_address | Value: {mac}")
            if infected_host.get('data_sources', {}).get('mac'):
                text_parts.append(f" | Source: {infected_host['data_sources']['mac']}")
            text_parts.append("\n")

        if user != 'Unknown':
            text_parts.append(f"Field: user_account | Value: {user}")
            if infected_host.get('data_sources', {}).get('user_account'):
                text_parts.append(f" | Source: {infected_host['data_sources']['user_account']}")
            text_parts.append("\n")

        if domain != 'Unknown':
            text_parts.append(f"Field: domain | Value: {domain}")
            if infected_host.get('data_sources', {}).get('domain'):
                text_parts.append(f" | Source: {infected_host['data_sources']['domain']}")
            text_parts.append("\n")

        if os_info != 'Unknown':
            text_parts.append(f"Field: os_version | Value: {os_info}")
            if infected_host.get('data_sources', {}).get('os_info'):
                text_parts.append(f" | Source: {infected_host['data_sources']['os_info']}")
            text_parts.append("\n")

        text_parts.append("\n## Infection Status\n")
        text_parts.append(f"Status: INFECTED")
        text_parts.append(f"Confidence: {infected_host.get('infection_confidence', 'unknown')}\n")
        text_parts.append(f"Malicious Connections: {infected_host.get('malicious_connections_count', 0)}\n")
        text_parts.append(f"First Seen: {infected_host.get('first_seen', 'Unknown')}\n")
        text_parts.append(f"Total Packets: {infected_host.get('total_packets', 0)}\n")

        text_parts.append("\n## Forensic Questions and Answers\n")
        text_parts.append(f"Q: What is the IP address of the infected client?\n")
        text_parts.append(f"A: {ip}\n\n")

        if hostname != 'Unknown':
            text_parts.append(f"Q: What is the hostname of the infected client?\n")
            text_parts.append(f"A: {hostname}\n\n")

        if mac != 'Unknown':
            text_parts.append(f"Q: What is the MAC address of the infected client?\n")
            text_parts.append(f"A: {mac}\n\n")

        if user != 'Unknown':
            text_parts.append(f"Q: What is the user account name from the infected host?\n")
            text_parts.append(f"A: {user}\n\n")

        if domain != 'Unknown':
            text_parts.append(f"Q: What is the domain name?\n")
            text_parts.append(f"A: {domain}\n\n")

        text_parts.append("## Summary\n")
        summary = f"The infected Windows client at IP address {ip}"
        if hostname != 'Unknown':
            summary += f" with hostname {hostname}"
        if mac != 'Unknown':
            summary += f" and MAC address {mac}"
        summary += " has been compromised."
        if user != 'Unknown':
            summary += f" The user account {user} was logged in when the infection occurred."
        text_parts.append(summary)

        text_parts.append("\n\n## Keywords\n")
        keywords = ['infected', 'client', 'compromised', 'host', 'victim', 'machine',
                   'malware', 'Windows', 'forensic', 'investigation']
        if hostname != 'Unknown':
            keywords.extend(['hostname', 'computer name', hostname])
        if mac != 'Unknown':
            keywords.extend(['MAC address', 'hardware address', mac])
        keywords.extend([ip])
        text_parts.append(', '.join(keywords))

        return ''.join(text_parts)

    @staticmethod
    def flatten_timeline(timeline: List[Dict[str, Any]]) -> str:
        text_parts = []

        text_parts.append("=== INFECTION TIMELINE ===\n")
        text_parts.append("Chronological sequence of malware infection events:\n\n")

        for event in timeline[:15]:
            timestamp = event.get('timestamp', 'N/A')
            description = event.get('description', 'Unknown event')
            text_parts.append(f"Time: {timestamp} | Event: {description}\n")

        text_parts.append(f"\nTotal timeline events: {len(timeline)}")

        return ''.join(text_parts)

    @staticmethod
    def flatten_hosts_inventory(hosts: Dict[str, Any], arp_table: Dict[str, str] = None) -> str:
        text_parts = []

        text_parts.append("=== ALL NETWORK HOSTS INVENTORY ===\n")
        text_parts.append("Complete list of hosts identified in the network:\n\n")

        for ip, host_info in list(hosts.items())[:30]:
            host_desc = f"Host: {ip}"
            if host_info.get('hostnames'):
                host_desc += f" | Hostname: {host_info['hostnames'][0]}"
            if host_info.get('mac_addresses'):
                host_desc += f" | MAC: {host_info['mac_addresses'][0]}"
            if host_info.get('user_accounts'):
                host_desc += f" | User: {host_info['user_accounts'][0]}"
            status = 'INFECTED' if host_info.get('is_infected') else 'Clean'
            host_desc += f" | Status: {status}"
            text_parts.append(host_desc + "\n")

        text_parts.append(f"\nTotal hosts: {len(hosts)}\n")

        if arp_table:
            text_parts.append("\n=== ARP TABLE (MAC to IP Mappings) ===\n")
            for ip, mac in list(arp_table.items())[:20]:
                text_parts.append(f"{ip} -> {mac}\n")

        return ''.join(text_parts)

    @staticmethod
    def flatten_packet_data(packets: List[Dict[str, Any]], ips: set, domains: set,
                           protocols: set, threats: List[Dict[str, Any]]) -> str:
        text_parts = []

        text_parts.append(f"Network traffic segment with {len(packets)} packets.\n\n")

        if threats:
            text_parts.append(f"=== VIRUSTOTAL THREAT INTELLIGENCE ({len(threats)} threats detected) ===\n")
            for threat in threats[:10]:
                entity = threat['entity']
                info = threat['info']
                threat_desc = f"THREAT: {info['type'].upper()} {entity} "
                threat_desc += f"flagged by {info['malicious_count']} security vendors"
                if info.get('threat_label'):
                    threat_desc += f" as {info['threat_label']}"
                text_parts.append(threat_desc + "\n")
            text_parts.append("\n")

        if protocols:
            text_parts.append(f"Protocols: {', '.join(list(protocols))}\n")

        if ips:
            text_parts.append(f"IP Addresses: {', '.join(list(ips)[:15])}\n")

        if domains:
            text_parts.append(f"Domains: {', '.join(list(domains)[:15])}\n")

        http_requests = []
        dns_queries = []

        for packet in packets[:20]:
            if 'http' in packet:
                http_info = packet['http']
                method = http_info.get('method', 'GET')
                host = http_info.get('host', 'unknown')
                uri = http_info.get('uri', '/')
                http_requests.append(f"{method} {host}{uri}")

            if 'dns' in packet:
                query_name = packet['dns'].get('query_name', '')
                if query_name:
                    dns_queries.append(query_name)

        if http_requests:
            text_parts.append(f"\nHTTP Requests:\n")
            for req in http_requests[:8]:
                text_parts.append(f"  - {req}\n")

        if dns_queries:
            text_parts.append(f"\nDNS Queries:\n")
            for query in dns_queries[:12]:
                text_parts.append(f"  - {query}\n")

        return ''.join(text_parts)
