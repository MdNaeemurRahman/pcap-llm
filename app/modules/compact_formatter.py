"""
Compact context formatter for LLM consumption.
Creates dense but highly readable summaries optimized for small context windows.
"""

from typing import Dict, List, Any, Optional


class CompactFormatter:
    """Formats enhanced summaries into compact, LLM-optimized context."""

    def format_enhanced_summary_for_llm(self, enhanced_summary: Dict[str, Any]) -> str:
        """Format an enhanced summary into a compact context for LLM."""

        parts = []

        # Navigation header (helps LLM understand what's available)
        parts.append(self._format_navigation_header(enhanced_summary))
        parts.append("")

        # Threat summary (ALWAYS first and most prominent)
        threat_section = self._format_threat_narrative(enhanced_summary.get('threat_summary', {}))
        if threat_section:
            parts.append(threat_section)
            parts.append("")

        # Behavioral patterns (if any detected)
        patterns = enhanced_summary.get('behavioral_patterns', [])
        if patterns:
            parts.append("=== BEHAVIORAL ANOMALIES ===")
            for pattern in patterns[:5]:  # Top 5 patterns
                parts.append(f"⚠ {pattern}")
            parts.append("")

        # Core statistics (compact format)
        parts.append(self._format_statistics(enhanced_summary))
        parts.append("")

        # Top entities (threat-prioritized, compact notation)
        parts.append(self._format_top_entities(enhanced_summary.get('top_entities', {})))
        parts.append("")

        # HTTP activity summary (grouped by domain)
        http_summary = enhanced_summary.get('http_activity', {})
        if http_summary and http_summary.get('domain_groups'):
            parts.append(self._format_http_activity(http_summary))
            parts.append("")

        # DNS activity summary
        dns_summary = enhanced_summary.get('dns_activity', {})
        if dns_summary and dns_summary.get('resolutions'):
            parts.append(self._format_dns_activity(dns_summary))
            parts.append("")

        # TCP connections (top important ones only)
        tcp_connections = enhanced_summary.get('tcp_connections', [])
        if tcp_connections:
            parts.append(self._format_tcp_connections(tcp_connections[:10]))  # Top 10
            parts.append("")

        # IP-Domain relationships (compact map)
        relationships = enhanced_summary.get('ip_domain_relationships', {})
        if relationships and len(relationships) > 0:
            parts.append(self._format_relationships(relationships))
            parts.append("")

        return "\n".join(parts)

    def _format_navigation_header(self, enhanced_summary: Dict[str, Any]) -> str:
        """Create a navigation header showing what data is available."""

        stats = enhanced_summary.get('statistics', {})
        file_info = enhanced_summary.get('file_info', {})
        threat_summary = enhanced_summary.get('threat_summary', {})

        lines = [
            "=== PCAP ANALYSIS SUMMARY ===",
            f"File: {file_info.get('filename', 'Unknown')} | Hash: {file_info.get('file_hash', 'N/A')[:16]}...",
            f"Traffic: {stats.get('total_packets', 0)} packets | {stats.get('unique_ips_count', 0)} IPs | {stats.get('unique_domains_count', 0)} domains",
            f"Threats: {threat_summary.get('severity', 'CLEAN')} - {threat_summary.get('threat_count', 0)} malicious, {threat_summary.get('suspicious_count', 0)} suspicious",
        ]

        # Add protocol distribution
        protocols = stats.get('top_protocols', {})
        if protocols:
            proto_str = ", ".join([f"{p}({c})" for p, c in list(protocols.items())[:5]])
            lines.append(f"Protocols: {proto_str}")

        # Data scope note
        entity_stats = enhanced_summary.get('entity_statistics', {})
        lines.append(f"Scope: Showing top 50 IPs, top 50 domains (from {entity_stats.get('total_ips', 0)} total IPs, {entity_stats.get('total_domains', 0)} total domains)")

        return "\n".join(lines)

    def _format_threat_narrative(self, threat_summary: Dict[str, Any]) -> str:
        """Format threat narrative in a compact but clear format."""

        if not threat_summary or threat_summary.get('severity') == 'CLEAN':
            return ""

        lines = [
            f"=== THREAT INTELLIGENCE ({threat_summary.get('severity', 'UNKNOWN')} SEVERITY) ===",
            threat_summary.get('summary', 'Threats detected'),
            ""
        ]

        # List each threat compactly
        threats = threat_summary.get('threats', [])
        if threats:
            lines.append("Detected Threats:")
            for i, threat in enumerate(threats, 1):
                # Compact format: Type | Value | Severity | Vendors | Label
                threat_line = f"{i}. {threat['type'].upper()} {threat['value']}"
                threat_line += f" | {threat['severity'].upper()}"
                threat_line += f" | {threat['malicious_vendors']} vendors"
                if threat.get('threat_label'):
                    threat_line += f" | {threat['threat_label']}"

                # Add context if available
                if threat.get('packet_count'):
                    threat_line += f" | {threat['packet_count']} packets"
                if threat.get('request_count'):
                    threat_line += f" | {threat['request_count']} requests"

                lines.append(threat_line)

                # Top detection engines (very compact)
                engines = threat.get('detection_engines', [])
                if engines:
                    engine_str = ", ".join([f"{e['engine']}:{e['result']}" for e in engines[:2]])
                    lines.append(f"   Detections: {engine_str}")

        # Recommendations
        recommendations = threat_summary.get('recommendations', [])
        if recommendations:
            lines.append("")
            lines.append("Recommendations:")
            for rec in recommendations:
                lines.append(f"• {rec}")

        return "\n".join(lines)

    def _format_statistics(self, enhanced_summary: Dict[str, Any]) -> str:
        """Format core statistics in compact form."""

        stats = enhanced_summary.get('statistics', {})
        entity_stats = enhanced_summary.get('entity_statistics', {})

        lines = [
            "=== TRAFFIC STATISTICS ===",
            f"Total Packets: {stats.get('total_packets', 0)} | IPs: {stats.get('unique_ips_count', 0)} ({stats.get('threat_ips_count', 0)} threats) | Domains: {stats.get('unique_domains_count', 0)} ({stats.get('threat_domains_count', 0)} threats)"
        ]

        # HTTP/DNS behavior if available
        http_behavior = enhanced_summary.get('http_behavior_analysis', {})
        dns_behavior = enhanced_summary.get('dns_behavior_analysis', {})

        if http_behavior:
            lines.append(f"HTTP: {http_behavior.get('total_requests', 0)} requests to {len(http_behavior.get('domains_contacted', []))} domains")
        if dns_behavior:
            lines.append(f"DNS: {dns_behavior.get('total_queries', 0)} queries for {len(dns_behavior.get('unique_domains', []))} domains ({dns_behavior.get('failed_resolutions', 0)} failed)")

        return "\n".join(lines)

    def _format_top_entities(self, top_entities: Dict[str, Any]) -> str:
        """Format top entities (IPs, domains, flows) in compact notation."""

        lines = ["=== TOP ENTITIES (threat-prioritized) ==="]

        # Top IPs (compact: IP | packets | bytes | protocols | status)
        ips = top_entities.get('ips', [])
        if ips:
            lines.append("")
            lines.append("Top IPs:")
            for ip_data in ips[:15]:  # Top 15
                ip = ip_data.get('ip', 'Unknown')
                pkt_count = ip_data.get('packet_count', 0)
                bytes_count = ip_data.get('total_bytes', 0)
                protocols = ",".join(ip_data.get('protocols', [])[:3])
                status = ip_data.get('threat_status', 'clean').upper()

                ip_line = f"  {ip} | {pkt_count}pkt | {bytes_count//1000}KB | {protocols}"

                if status != 'CLEAN':
                    ip_line += f" | ⚠ {status}"
                    if ip_data.get('threat_label'):
                        ip_line += f" ({ip_data['threat_label']})"

                lines.append(ip_line)

        # Top Domains (compact: domain | requests | bytes | status)
        domains = top_entities.get('domains', [])
        if domains:
            lines.append("")
            lines.append("Top Domains:")
            for domain_data in domains[:15]:  # Top 15
                domain = domain_data.get('domain', 'Unknown')
                req_count = domain_data.get('request_count', 0)
                bytes_count = domain_data.get('total_bytes', 0)
                status = domain_data.get('threat_status', 'clean').upper()

                domain_line = f"  {domain} | {req_count} req | {bytes_count//1000}KB"

                if status != 'CLEAN':
                    domain_line += f" | ⚠ {status}"
                    if domain_data.get('threat_label'):
                        domain_line += f" ({domain_data['threat_label']})"

                # Show resolved IPs if available
                resolved_ips = domain_data.get('resolved_ips', [])
                if resolved_ips:
                    domain_line += f" -> {', '.join(resolved_ips[:2])}"

                lines.append(domain_line)

        # Top Flows (very compact)
        flows = top_entities.get('flows', [])
        if flows:
            lines.append("")
            lines.append("Top Flows:")
            for flow_data in flows[:10]:  # Top 10
                flow_key = flow_data.get('flow_key', 'Unknown')
                pkt_count = flow_data.get('packet_count', 0)
                bytes_count = flow_data.get('total_bytes', 0)
                protocol = flow_data.get('protocol', 'UNKNOWN')

                flow_line = f"  {flow_key} | {protocol} | {pkt_count}pkt | {bytes_count//1000}KB"

                if flow_data.get('involves_threat'):
                    flow_line += " | ⚠ THREAT"

                lines.append(flow_line)

        return "\n".join(lines)

    def _format_http_activity(self, http_summary: Dict[str, Any]) -> str:
        """Format HTTP activity in grouped, compact format."""

        lines = [
            "=== HTTP ACTIVITY ===",
            f"Total: {http_summary.get('total_sessions', 0)} requests to {http_summary.get('unique_domains', 0)} domains",
            ""
        ]

        domain_groups = http_summary.get('domain_groups', [])
        for group in domain_groups[:10]:  # Top 10 domain groups
            domain = group.get('domain', 'Unknown')
            req_count = group.get('request_count', 0)
            status = group.get('threat_status', 'clean')

            # Methods and status codes (compact)
            methods = group.get('methods', {})
            status_codes = group.get('status_codes', {})
            method_str = ",".join([f"{m}({c})" for m, c in methods.items()])
            status_str = ",".join([f"{s}({c})" for s, c in list(status_codes.items())[:3]])

            group_line = f"{domain} | {req_count} req | Methods:{method_str} | Status:{status_str}"

            if status != 'clean':
                group_line += f" | ⚠ {status.upper()}"

            lines.append(group_line)

            # Sample requests (very compact, only for threats or first 3 groups)
            if status != 'clean' or domain_groups.index(group) < 3:
                samples = group.get('sample_requests', [])
                for sample in samples[:2]:  # Max 2 samples
                    lines.append(f"  └─ {sample.get('method', 'GET')} {sample.get('uri', '/')} ({sample.get('status_code', 'N/A')})")

        return "\n".join(lines)

    def _format_dns_activity(self, dns_summary: Dict[str, Any]) -> str:
        """Format DNS activity in grouped, compact format."""

        lines = [
            "=== DNS ACTIVITY ===",
            f"Total: {dns_summary.get('total_queries', 0)} queries for {dns_summary.get('unique_domains', 0)} domains",
            ""
        ]

        resolutions = dns_summary.get('resolutions', [])
        for res in resolutions[:10]:  # Top 10
            domain = res.get('domain', 'Unknown')
            query_count = res.get('query_count', 0)
            resolved_ips = res.get('resolved_ips', [])
            failed = res.get('failed_count', 0)
            status = res.get('threat_status', 'clean')

            res_line = f"{domain} | {query_count} queries"

            if resolved_ips:
                res_line += f" -> {', '.join(resolved_ips[:3])}"
            if failed > 0:
                res_line += f" | {failed} failed"

            if status != 'clean':
                res_line += f" | ⚠ {status.upper()}"

            lines.append(res_line)

        return "\n".join(lines)

    def _format_tcp_connections(self, tcp_connections: List[Dict[str, Any]]) -> str:
        """Format TCP connections in compact format."""

        lines = [
            "=== TCP CONNECTIONS (Top by importance) ==="
        ]

        for conn in tcp_connections:
            src = f"{conn.get('src_ip', 'N/A')}:{conn.get('src_port', 'N/A')}"
            dst = f"{conn.get('dst_ip', 'N/A')}:{conn.get('dst_port', 'N/A')}"
            state = conn.get('state', 'UNKNOWN')
            quality = conn.get('quality', 'unknown')
            service = conn.get('service', 'Unknown')

            conn_line = f"{src} -> {dst} | {service} | {state} | {quality}"

            lines.append(conn_line)

        return "\n".join(lines)

    def _format_relationships(self, relationships: Dict[str, List[str]]) -> str:
        """Format IP-domain relationships in compact map."""

        lines = [
            "=== DOMAIN -> IP RELATIONSHIPS ==="
        ]

        # Show top 15 relationships
        for domain, ips in list(relationships.items())[:15]:
            ip_str = ", ".join(ips[:5])  # Max 5 IPs per domain
            lines.append(f"{domain} -> {ip_str}")

        return "\n".join(lines)
