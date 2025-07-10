import httpx
import hashlib
import json
from typing import Dict, Any, Optional
import asyncio
import logging
from app.core.config import settings

logger = logging.getLogger(__name__)

class APIIntegrator:
    """Integrates with external threat intelligence APIs"""
    
    def __init__(self):
        self.virustotal_base_url = "https://www.virustotal.com/vtapi/v2"
        self.hybrid_analysis_base_url = "https://www.hybrid-analysis.com/api/v2"
        self.timeout = 30
        
    async def analyze_file(self, file_path: str, file_hash: str) -> Dict[str, Any]:
        """Analyze file using multiple threat intelligence APIs"""
        results = {}
        
        # Run API calls in parallel for better performance
        tasks = []
        
        if settings.virustotal_api_key:
            tasks.append(self._analyze_with_virustotal(file_hash))
        
        if settings.hybrid_analysis_api_key:
            tasks.append(self._analyze_with_hybrid_analysis(file_path))
        
        # Add other free APIs that don't require keys
        tasks.append(self._analyze_with_malware_bazaar(file_hash))
        
        # Execute all API calls concurrently
        if tasks:
            api_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            if settings.virustotal_api_key and len(api_results) > 0:
                results['virustotal'] = api_results[0] if not isinstance(api_results[0], Exception) else {'error': str(api_results[0])}
            
            if settings.hybrid_analysis_api_key and len(api_results) > 1:
                results['hybrid_analysis'] = api_results[1] if not isinstance(api_results[1], Exception) else {'error': str(api_results[1])}
            
            # Malware Bazaar result
            bazaar_index = len(tasks) - 1
            results['malware_bazaar'] = api_results[bazaar_index] if not isinstance(api_results[bazaar_index], Exception) else {'error': str(api_results[bazaar_index])}
        
        return results
    
    async def _analyze_with_virustotal(self, file_hash: str) -> Dict[str, Any]:
        """Analyze file hash with VirusTotal API"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # First, try to get existing report
                params = {
                    'apikey': settings.virustotal_api_key,
                    'resource': file_hash
                }
                
                response = await client.get(
                    f"{self.virustotal_base_url}/file/report",
                    params=params
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if data.get('response_code') == 1:  # Report exists
                        return {
                            'status': 'found',
                            'scan_date': data.get('scan_date'),
                            'total_scans': data.get('total', 0),
                            'malicious_count': data.get('positives', 0),
                            'detection_ratio': f"{data.get('positives', 0)}/{data.get('total', 0)}",
                            'detections': data.get('scans', {}),
                            'permalink': data.get('permalink'),
                            'raw_response': data
                        }
                    else:
                        return {
                            'status': 'not_found',
                            'message': 'File not found in VirusTotal database'
                        }
                else:
                    return {
                        'status': 'error',
                        'message': f"HTTP {response.status_code}: {response.text}"
                    }
                    
        except Exception as e:
            logger.error(f"VirusTotal API error: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }
    
    async def _analyze_with_hybrid_analysis(self, file_path: str) -> Dict[str, Any]:
        """Analyze file with Hybrid Analysis API"""
        try:
            # Note: This is a simplified implementation
            # In production, you'd need to implement file upload and polling for results
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                headers = {
                    'api-key': settings.hybrid_analysis_api_key,
                    'user-agent': 'Falcon Sandbox'
                }
                
                # For this demo, we'll just return a mock response
                # In production, you'd upload the file and wait for analysis
                return {
                    'status': 'demo',
                    'message': 'Hybrid Analysis integration would require file upload and polling',
                    'threat_score': 0,
                    'verdict': 'no specific threat'
                }
                
        except Exception as e:
            logger.error(f"Hybrid Analysis API error: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }
    
    async def _analyze_with_malware_bazaar(self, file_hash: str) -> Dict[str, Any]:
        """Analyze file hash with MalwareBazaar (free API)"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # MalwareBazaar API endpoint
                url = "https://mb-api.abuse.ch/api/v1/"
                
                data = {
                    'query': 'get_info',
                    'hash': file_hash
                }
                
                response = await client.post(url, data=data)
                
                if response.status_code == 200:
                    result = response.json()
                    
                    if result.get('query_status') == 'ok':
                        file_info = result.get('data', [])
                        if file_info:
                            info = file_info[0]
                            return {
                                'status': 'found',
                                'first_seen': info.get('first_seen'),
                                'last_seen': info.get('last_seen'),
                                'file_name': info.get('file_name'),
                                'file_type': info.get('file_type'),
                                'mime_type': info.get('mime_type'),
                                'signature': info.get('signature'),
                                'intelligence': info.get('intelligence', {}),
                                'tags': info.get('tags', []),
                                'raw_response': result
                            }
                        else:
                            return {
                                'status': 'not_found',
                                'message': 'File not found in MalwareBazaar database'
                            }
                    else:
                        return {
                            'status': 'not_found',
                            'message': result.get('query_status', 'Unknown error')
                        }
                else:
                    return {
                        'status': 'error',
                        'message': f"HTTP {response.status_code}: {response.text}"
                    }
                    
        except Exception as e:
            logger.error(f"MalwareBazaar API error: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }
    
    async def _analyze_with_urlvoid(self, url: str) -> Dict[str, Any]:
        """Analyze URL with URLVoid (for URL-based threats)"""
        try:
            # URLVoid API implementation would go here
            # This is a placeholder for URL analysis
            return {
                'status': 'not_implemented',
                'message': 'URLVoid integration placeholder'
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': str(e)
            }
    
    async def get_threat_intelligence(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """Get threat intelligence for a specific indicator"""
        results = {}
        
        if indicator_type == 'hash':
            if settings.virustotal_api_key:
                results['virustotal'] = await self._analyze_with_virustotal(indicator)
            results['malware_bazaar'] = await self._analyze_with_malware_bazaar(indicator)
        elif indicator_type == 'url':
            results['urlvoid'] = await self._analyze_with_urlvoid(indicator)
        
        return results
    
    def _extract_iocs_from_results(self, api_results: Dict[str, Any]) -> Dict[str, Any]:
        """Extract Indicators of Compromise from API results"""
        iocs = {
            'file_hashes': [],
            'domains': [],
            'ips': [],
            'urls': [],
            'registry_keys': [],
            'file_paths': []
        }
        
        # Extract IOCs from VirusTotal results
        vt_results = api_results.get('virustotal', {})
        if vt_results.get('status') == 'found':
            raw_response = vt_results.get('raw_response', {})
            
            # Extract additional hashes if available
            for hash_type in ['md5', 'sha1', 'sha256']:
                if hash_type in raw_response:
                    iocs['file_hashes'].append({
                        'type': hash_type,
                        'value': raw_response[hash_type]
                    })
        
        # Extract IOCs from other sources...
        
        return iocs