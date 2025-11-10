import time
import requests
from typing import Dict, List, Any, Optional
from datetime import datetime


class VirusTotalClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "accept": "application/json",
            "X-Apikey": api_key
        }
        self.rate_limit_delay = 15

    def _make_request(self, endpoint: str) -> Optional[Dict[str, Any]]:
        url = f"{self.base_url}/{endpoint}"
        try:
            print(f"[VirusTotal] Sending request to: {endpoint}")
            response = requests.get(url, headers=self.headers, timeout=10)

            if response.status_code == 200:
                print(f"[VirusTotal] Response received: OK (200)")
                return response.json()
            elif response.status_code == 404:
                print(f"[VirusTotal] Response received: Not Found (404)")
                return None
            elif response.status_code == 429:
                print(f"[VirusTotal] Rate limit hit, waiting {self.rate_limit_delay} seconds...")
                time.sleep(self.rate_limit_delay)
                return self._make_request(endpoint)
            else:
                print(f"[VirusTotal] API error: {response.status_code}")
                return None
        except Exception as e:
            print(f"[VirusTotal] Request failed: {str(e)}")
            return None

    def query_file_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        endpoint = f"files/{file_hash}"
        result = self._make_request(endpoint)

        if result and 'data' in result:
            return self._parse_vt_response(result['data'], 'file', file_hash)
        return None

    def query_ip_address(self, ip: str) -> Optional[Dict[str, Any]]:
        endpoint = f"ip_addresses/{ip}"
        result = self._make_request(endpoint)

        if result and 'data' in result:
            return self._parse_vt_response(result['data'], 'ip', ip)
        return None

    def query_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        endpoint = f"domains/{domain}"
        result = self._make_request(endpoint)

        if result and 'data' in result:
            return self._parse_vt_response(result['data'], 'domain', domain)
        return None

    def _parse_vt_response(self, data: Dict[str, Any], entity_type: str, entity_value: str) -> Dict[str, Any]:
        attributes = data.get('attributes', {})
        last_analysis_stats = attributes.get('last_analysis_stats', {})

        parsed = {
            'entity_type': entity_type,
            'entity_value': entity_value,
            'malicious_count': last_analysis_stats.get('malicious', 0),
            'suspicious_count': last_analysis_stats.get('suspicious', 0),
            'harmless_count': last_analysis_stats.get('harmless', 0),
            'undetected_count': last_analysis_stats.get('undetected', 0),
            'last_analysis_stats': last_analysis_stats,
            'category': attributes.get('categories', {}) if entity_type == 'domain' else None,
            'reputation': attributes.get('reputation', 0),
            'queried_at': datetime.utcnow().isoformat()
        }

        return parsed

    def batch_query_entities(self, ips: List[str], domains: List[str]) -> List[Dict[str, Any]]:
        results = []

        print(f"[VirusTotal] Starting batch query: {len(ips)} IPs and {len(domains)} domains")

        for idx, ip in enumerate(ips, 1):
            print(f"[VirusTotal] Querying IP {idx}/{len(ips)}: {ip}")
            result = self.query_ip_address(ip)
            if result:
                results.append(result)
            time.sleep(self.rate_limit_delay)

        for idx, domain in enumerate(domains, 1):
            print(f"[VirusTotal] Querying domain {idx}/{len(domains)}: {domain}")
            result = self.query_domain(domain)
            if result:
                results.append(result)
            time.sleep(self.rate_limit_delay)

        print(f"[VirusTotal] Batch query complete: {len(results)} results retrieved")
        return results

    def enrich_json_with_vt(self, json_data: Dict[str, Any], vt_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        vt_by_entity = {r['entity_value']: r for r in vt_results}

        enriched_data = json_data.copy()
        enriched_data['virustotal_results'] = {
            'summary': {
                'total_queried': len(vt_results),
                'malicious_entities': len([r for r in vt_results if r['malicious_count'] > 0]),
                'suspicious_entities': len([r for r in vt_results if r['suspicious_count'] > 0])
            },
            'flagged_entities': [r for r in vt_results if r['malicious_count'] > 0 or r['suspicious_count'] > 0],
            'all_results': vt_results
        }

        if 'unique_entities' in json_data:
            enriched_ips = []
            for ip in json_data['unique_entities'].get('ips', []):
                ip_data = {'ip': ip}
                if ip in vt_by_entity:
                    ip_data['vt_info'] = vt_by_entity[ip]
                enriched_ips.append(ip_data)

            enriched_domains = []
            for domain in json_data['unique_entities'].get('domains', []):
                domain_data = {'domain': domain}
                if domain in vt_by_entity:
                    domain_data['vt_info'] = vt_by_entity[domain]
                enriched_domains.append(domain_data)

            enriched_data['unique_entities']['ips_with_vt'] = enriched_ips
            enriched_data['unique_entities']['domains_with_vt'] = enriched_domains

        return enriched_data

    def get_flagged_entities(self, vt_results: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        flagged = {
            'malicious': [],
            'suspicious': []
        }

        for result in vt_results:
            if result['malicious_count'] > 0:
                flagged['malicious'].append(result)
            elif result['suspicious_count'] > 0:
                flagged['suspicious'].append(result)

        return flagged
