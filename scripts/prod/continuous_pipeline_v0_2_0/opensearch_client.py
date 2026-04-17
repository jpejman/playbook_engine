"""
OpenSearch NVD client
Version: v0.2.0
Timestamp (UTC): 2026-04-16T23:45:00Z
"""

from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request
from typing import Any

from .config import ContinuousPipelineConfig


class OpenSearchClient:
    def __init__(self):
        self.base_url = ContinuousPipelineConfig.OPENSEARCH_URL.rstrip('/')
        self.index = ContinuousPipelineConfig.OPENSEARCH_INDEX
        self.username = ContinuousPipelineConfig.OPENSEARCH_USERNAME
        self.password = ContinuousPipelineConfig.OPENSEARCH_PASSWORD
        self.verify_tls = ContinuousPipelineConfig.OPENSEARCH_VERIFY_TLS

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        data = None
        headers = {'Content-Type': 'application/json'}
        if payload is not None:
            data = json.dumps(payload).encode('utf-8')
        if self.username:
            token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            headers['Authorization'] = f'Basic {token}'
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        context = None
        if url.startswith('https://') and not self.verify_tls:
            context = ssl._create_unverified_context()
        try:
            with urllib.request.urlopen(req, context=context, timeout=30) as resp:
                return json.loads(resp.read().decode('utf-8'))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode('utf-8', errors='replace')
            raise RuntimeError(f'OpenSearch HTTP {exc.code}: {body}') from exc
        except Exception as exc:
            raise RuntimeError(f'OpenSearch request failed: {exc}') from exc

    def search_candidates(self, from_offset: int = 0, page_size: int = 100) -> list[dict[str, Any]]:
        body = {
            'from': from_offset,
            'size': page_size,
            'sort': [
                {'metrics.cvssMetricV31.0.cvssData.baseScore': {'order': 'desc', 'unmapped_type': 'float'}},
                {'published': {'order': 'desc', 'unmapped_type': 'date'}},
            ],
            '_source': True,
            'query': {
                'bool': {
                    'must': [{'match_all': {}}],
                    'must_not': [
                        {'wildcard': {'id.keyword': 'CVE-TEST*'}},
                        {'wildcard': {'id.keyword': 'CVE-DEMO*'}},
                    ],
                }
            },
        }
        result = self._request('POST', f'/{self.index}/_search', body)
        hits = result.get('hits', {}).get('hits', [])
        return [self._normalize_hit(hit) for hit in hits]

    def fetch_cve(self, cve_id: str) -> dict[str, Any]:
        body = {
            'size': 1,
            '_source': True,
            'query': {
                'bool': {
                    'should': [
                        {'term': {'id.keyword': cve_id}},
                        {'term': {'cve.id.keyword': cve_id}},
                        {'match_phrase': {'id': cve_id}},
                        {'match_phrase': {'cve.id': cve_id}},
                    ],
                    'minimum_should_match': 1,
                }
            },
        }
        result = self._request('POST', f'/{self.index}/_search', body)
        hits = result.get('hits', {}).get('hits', [])
        if not hits:
            raise RuntimeError(f'OpenSearch returned no document for {cve_id}')
        return self._normalize_hit(hits[0])

    def _normalize_hit(self, hit: dict[str, Any]) -> dict[str, Any]:
        source = hit.get('_source', {}) or {}
        cve_id = source.get('id') or source.get('cve', {}).get('id') or hit.get('_id')
        descriptions = source.get('descriptions') or source.get('cve', {}).get('descriptions') or []
        description = ''
        for item in descriptions:
            if isinstance(item, dict) and item.get('lang') in {None, 'en'} and item.get('value'):
                description = item['value']
                break
        if not description and isinstance(source.get('description'), str):
            description = source['description']
        return {
            'cve_id': cve_id,
            'source_doc_id': hit.get('_id'),
            'raw_source': source,
            'description': description,
            'published': source.get('published') or source.get('cve', {}).get('published'),
            'last_modified': source.get('lastModified') or source.get('cve', {}).get('lastModified'),
            'vendor': self._extract_vendor(source),
            'product': self._extract_product(source),
            'severity': self._extract_severity(source),
            'cvss_score': self._extract_cvss(source),
            'references': self._extract_references(source),
        }

    def _extract_vendor(self, source: dict[str, Any]) -> str | None:
        vendor = source.get('vendor')
        if vendor:
            return str(vendor)
        configurations = source.get('configurations', []) or source.get('cve', {}).get('configurations', [])
        for conf in configurations:
            nodes = conf.get('nodes', []) if isinstance(conf, dict) else []
            for node in nodes:
                for match in node.get('cpeMatch', []):
                    criteria = match.get('criteria') or match.get('cpe23Uri')
                    if criteria and ':' in criteria:
                        parts = criteria.split(':')
                        if len(parts) > 3:
                            return parts[3]
        return None

    def _extract_product(self, source: dict[str, Any]) -> str | None:
        product = source.get('product')
        if product:
            return str(product)
        configurations = source.get('configurations', []) or source.get('cve', {}).get('configurations', [])
        for conf in configurations:
            nodes = conf.get('nodes', []) if isinstance(conf, dict) else []
            for node in nodes:
                for match in node.get('cpeMatch', []):
                    criteria = match.get('criteria') or match.get('cpe23Uri')
                    if criteria and ':' in criteria:
                        parts = criteria.split(':')
                        if len(parts) > 4:
                            return parts[4]
        return None

    def _extract_references(self, source: dict[str, Any]) -> list[str]:
        refs = source.get('references') or source.get('cve', {}).get('references') or []
        values = []
        for item in refs:
            if isinstance(item, dict) and item.get('url'):
                values.append(item['url'])
        return values

    def _extract_severity(self, source: dict[str, Any]) -> str | None:
        metrics = source.get('metrics', {})
        for key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            values = metrics.get(key) or metrics.get(f'{key}.0')
            if isinstance(values, list) and values:
                sev = values[0].get('cvssData', {}).get('baseSeverity')
                if sev:
                    return sev
        return source.get('severity')

    def _extract_cvss(self, source: dict[str, Any]) -> float | None:
        metrics = source.get('metrics', {})
        for key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            values = metrics.get(key) or metrics.get(f'{key}.0')
            if isinstance(values, list) and values:
                score = values[0].get('cvssData', {}).get('baseScore')
                if score is not None:
                    try:
                        return float(score)
                    except Exception:
                        return None
        score = source.get('cvss_score')
        try:
            return float(score) if score is not None else None
        except Exception:
            return None

    def diagnostic_info(self) -> dict[str, Any]:
        """Return diagnostic information about OpenSearch connection and index."""
        try:
            # Get cluster health
            health = self._request('GET', '/_cluster/health')
            
            # Get index info
            index_info = self._request('GET', f'/{self.index}')
            index_stats = index_info.get(self.index, {})
            
            # Get sample data
            sample_query = {
                'size': 3,
                '_source': ['id', 'cve.id', 'published'],
                'sort': [{'published': {'order': 'desc'}}]
            }
            sample_result = self._request('POST', f'/{self.index}/_search', sample_query)
            hits = sample_result.get('hits', {}).get('hits', [])
            sample_cves = []
            for hit in hits:
                source = hit.get('_source', {})
                cve_id = source.get('id') or source.get('cve', {}).get('id') or hit.get('_id')
                sample_cves.append(cve_id)
            
            return {
                'connected': True,
                'cluster_status': health.get('status'),
                'index_exists': bool(index_stats),
                'index_name': self.index,
                'document_count': index_stats.get('total', {}).get('docs', {}).get('count', 0),
                'sample_cves': sample_cves,
                'base_url': self.base_url,
            }
        except Exception as e:
            return {
                'connected': False,
                'error': str(e),
                'index_name': self.index,
                'base_url': self.base_url,
            }
