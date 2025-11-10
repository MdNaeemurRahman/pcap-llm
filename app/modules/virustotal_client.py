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

    def _convert_timestamp_to_iso(self, timestamp_value: Any) -> Optional[str]:
        """Convert Unix timestamp to ISO format datetime string."""
        if timestamp_value is None:
            return None

        try:
            if isinstance(timestamp_value, (int, float)):
                dt = datetime.fromtimestamp(timestamp_value)
                return dt.isoformat()
            elif isinstance(timestamp_value, str):
                try:
                    timestamp_int = int(timestamp_value)
                    dt = datetime.fromtimestamp(timestamp_int)
                    return dt.isoformat()
                except ValueError:
                    return timestamp_value
            return None
        except (ValueError, OSError, OverflowError) as e:
            print(f"Warning: Failed to convert timestamp {timestamp_value}: {str(e)}")
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

        if entity_type == 'file':
            parsed['file_type'] = attributes.get('type_description', 'Unknown')
            parsed['file_size'] = attributes.get('size', 0)
            parsed['md5'] = attributes.get('md5', '')
            parsed['sha1'] = attributes.get('sha1', '')
            parsed['sha256'] = attributes.get('sha256', '')

            first_submission = attributes.get('first_submission_date')
            if first_submission:
                parsed['first_submission_date'] = self._convert_timestamp_to_iso(first_submission)
            else:
                parsed['first_submission_date'] = None

            last_analysis = attributes.get('last_analysis_date')
            if last_analysis:
                parsed['last_analysis_date'] = self._convert_timestamp_to_iso(last_analysis)
            else:
                parsed['last_analysis_date'] = None

            popular_threat_classification = attributes.get('popular_threat_classification', {})
            if popular_threat_classification:
                parsed['threat_label'] = popular_threat_classification.get('suggested_threat_label', 'Unknown')
                parsed['threat_category'] = popular_threat_classification.get('popular_threat_category', [])

            last_analysis_results = attributes.get('last_analysis_results', {})
            if last_analysis_results:
                detected_engines = []
                for engine, result in last_analysis_results.items():
                    if result.get('category') in ['malicious', 'suspicious']:
                        detected_engines.append({
                            'engine': engine,
                            'category': result.get('category'),
                            'result': result.get('result', 'Unknown')
                        })
                parsed['detection_engines'] = detected_engines[:10]

            sandbox_verdicts = attributes.get('sandbox_verdicts', {})
            if sandbox_verdicts:
                parsed['sandbox_verdicts'] = []
                for sandbox, verdict in sandbox_verdicts.items():
                    if verdict:
                        parsed['sandbox_verdicts'].append({
                            'sandbox': sandbox,
                            'category': verdict.get('category', 'unknown'),
                            'malware_names': verdict.get('malware_names', [])
                        })

        return parsed

    def batch_query_entities(
        self,
        ips: List[str],
        domains: List[str],
        file_hashes: Optional[List[str]] = None,
        cached_results: Optional[List[Dict[str, Any]]] = None
    ) -> List[Dict[str, Any]]:
        results = []

        cached_entities = set()
        if cached_results:
            results.extend(cached_results)
            for cached in cached_results:
                cached_entities.add(cached['entity_value'])
            print(f"[VirusTotal] Found {len(cached_results)} cached results")

        ips_to_query = [ip for ip in ips if ip not in cached_entities]
        domains_to_query = [domain for domain in domains if domain not in cached_entities]
        hashes_to_query = []
        if file_hashes:
            hashes_to_query = [h for h in file_hashes if h not in cached_entities]

        total_to_query = len(ips_to_query) + len(domains_to_query) + len(hashes_to_query)
        print(f"[VirusTotal] Starting batch query: {len(ips_to_query)} IPs, {len(domains_to_query)} domains, and {len(hashes_to_query)} file hashes")
        print(f"[VirusTotal] Skipped {len(ips) - len(ips_to_query)} cached IPs and {len(domains) - len(domains_to_query)} cached domains")

        if total_to_query == 0:
            print(f"[VirusTotal] All entities already cached, skipping API calls")
            return results

        if hashes_to_query:
            for idx, file_hash in enumerate(hashes_to_query, 1):
                print(f"[VirusTotal] Querying file hash {idx}/{len(hashes_to_query)}: {file_hash[:16]}...")
                result = self.query_file_hash(file_hash)
                if result:
                    results.append(result)
                time.sleep(self.rate_limit_delay)

        for idx, ip in enumerate(ips_to_query, 1):
            print(f"[VirusTotal] Querying IP {idx}/{len(ips_to_query)}: {ip}")
            result = self.query_ip_address(ip)
            if result:
                results.append(result)
            time.sleep(self.rate_limit_delay)

        for idx, domain in enumerate(domains_to_query, 1):
            print(f"[VirusTotal] Querying domain {idx}/{len(domains_to_query)}: {domain}")
            result = self.query_domain(domain)
            if result:
                results.append(result)
            time.sleep(self.rate_limit_delay)

        print(f"[VirusTotal] Batch query complete: {len(results)} total results ({len(results) - len(cached_results or [])} new)")
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
