# app/elk_storage.py
"""
Elasticsearch storage module for Avighna2 SIEM
Replaces SQLite with Elasticsearch for better scalability and search capabilities
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError, NotFoundError
from elasticsearch_dsl import A, Q, Search


class ELKStorage:
    """Elasticsearch storage handler for SIEM data"""
    
    def __init__(self, host='localhost', port=9200):
        """Initialize Elasticsearch connection"""
        self.es = Elasticsearch([f'http://{host}:{port}'])
        self.logger = logging.getLogger(__name__)
        
        # Test connection
        try:
            if self.es.ping():
                self.logger.info("✅ Connected to Elasticsearch")
                self._create_indices()
            else:
                self.logger.error("❌ Cannot connect to Elasticsearch")
        except ConnectionError:
            self.logger.error("❌ Elasticsearch connection failed - using fallback mode")
            self.es = None
    
    def _create_indices(self):
        """Create necessary indices with proper mappings"""
        
        # SIEM Events Index
        events_mapping = {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "ip": {"type": "ip"},
                    "method": {"type": "keyword"},
                    "url": {"type": "text"},
                    "status_code": {"type": "integer"},
                    "response_size": {"type": "long"},
                    "user_agent": {"type": "text"},
                    "referer": {"type": "text"},
                    "country": {"type": "keyword"},
                    "city": {"type": "keyword"},
                    "threat_level": {"type": "keyword"},
                    "event_type": {"type": "keyword"},
                    "raw_log": {"type": "text"}
                }
            }
        }
        
        # Activity Log Index
        activity_mapping = {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "user": {"type": "keyword"},
                    "action": {"type": "keyword"},
                    "details": {"type": "text"},
                    "result": {"type": "text"},
                    "ip_address": {"type": "ip"},
                    "session_id": {"type": "keyword"}
                }
            }
        }
        
        # Threat Intelligence Index
        threat_mapping = {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "ip": {"type": "ip"},
                    "threat_type": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "description": {"type": "text"},
                    "indicators": {"type": "text"},
                    "source": {"type": "keyword"}
                }
            }
        }
        
        indices = {
            "siem-events": events_mapping,
            "siem-activity": activity_mapping, 
            "siem-threats": threat_mapping
        }
        
        for index_name, mapping in indices.items():
            if not self.es.indices.exists(index=index_name):
                self.es.indices.create(index=index_name, body=mapping)
                self.logger.info(f"✅ Created index: {index_name}")
    
    def index_events(self, events: List[Dict], index_name: str = "siem-events") -> bool:
        """Index security events into Elasticsearch"""
        if not self.es:
            return False
            
        try:
            actions = []
            for event in events:
                # Enrich event with timestamp
                if 'timestamp' not in event:
                    event['timestamp'] = datetime.now().isoformat()
                
                # Add threat analysis
                event['threat_level'] = self._analyze_threat_level(event)
                event['event_type'] = self._classify_event_type(event)
                
                action = {
                    "_index": index_name,
                    "_source": event
                }
                actions.append(action)
            
            # Bulk index
            from elasticsearch.helpers import bulk
            bulk(self.es, actions)
            self.logger.info(f"✅ Indexed {len(events)} events")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Failed to index events: {e}")
            return False
    
    def log_activity(self, user: str, action: str, details: str, result: str = None, ip_address: str = None):
        """Log user activity to Elasticsearch"""
        if not self.es:
            return
            
        activity = {
            "timestamp": datetime.now().isoformat(),
            "user": user,
            "action": action,
            "details": details,
            "result": result,
            "ip_address": ip_address,
            "session_id": self._generate_session_id()
        }
        
        try:
            self.es.index(index="siem-activity", body=activity)
        except Exception as e:
            self.logger.error(f"❌ Failed to log activity: {e}")
    
    def search_events(self, query: str = None, filters: Dict = None, size: int = 100) -> List[Dict]:
        """Advanced search across security events"""
        if not self.es:
            return []
        
        try:
            s = Search(using=self.es, index="siem-events")
            
            # Apply text search
            if query:
                s = s.query("multi_match", query=query, fields=["raw_log", "url", "user_agent"])
            
            # Apply filters
            if filters:
                for field, value in filters.items():
                    if field == "ip":
                        s = s.filter("term", ip=value)
                    elif field == "status_code":
                        s = s.filter("term", status_code=value)
                    elif field == "threat_level":
                        s = s.filter("term", threat_level=value)
                    elif field == "time_range":
                        start, end = value
                        s = s.filter("range", timestamp={"gte": start, "lte": end})
            
            # Execute search
            response = s[:size].execute()
            return [hit.to_dict() for hit in response]
            
        except Exception as e:
            self.logger.error(f"❌ Search failed: {e}")
            return []
    
    def get_threat_analytics(self) -> Dict[str, Any]:
        """Get comprehensive threat analytics using Elasticsearch aggregations"""
        if not self.es:
            return {}
        
        try:
            # Complex aggregation query
            agg_query = {
                "size": 0,
                "aggs": {
                    "top_threat_ips": {
                        "terms": {"field": "ip", "size": 10},
                        "aggs": {
                            "threat_levels": {
                                "terms": {"field": "threat_level"}
                            }
                        }
                    },
                    "status_codes": {
                        "terms": {"field": "status_code", "size": 20}
                    },
                    "threat_timeline": {
                        "date_histogram": {
                            "field": "timestamp",
                            "calendar_interval": "1h"
                        },
                        "aggs": {
                            "threat_count": {
                                "filter": {
                                    "terms": {"threat_level": ["high", "critical"]}
                                }
                            }
                        }
                    },
                    "geographic_threats": {
                        "terms": {"field": "country", "size": 15}
                    },
                    "attack_methods": {
                        "terms": {"field": "method", "size": 10}
                    }
                }
            }
            
            result = self.es.search(index="siem-events", body=agg_query)
            
            # Process aggregations
            analytics = {
                "top_threat_ips": [],
                "status_distribution": [],
                "threat_timeline": [],
                "geographic_distribution": [],
                "attack_methods": [],
                "total_events": result['hits']['total']['value']
            }
            
            # Process top threat IPs
            for bucket in result['aggregations']['top_threat_ips']['buckets']:
                analytics['top_threat_ips'].append({
                    "ip": bucket['key'],
                    "count": bucket['doc_count'],
                    "threat_levels": [t['key'] for t in bucket['threat_levels']['buckets']]
                })
            
            # Process other aggregations
            analytics['status_distribution'] = [
                {"code": b['key'], "count": b['doc_count']} 
                for b in result['aggregations']['status_codes']['buckets']
            ]
            
            analytics['geographic_distribution'] = [
                {"country": b['key'], "count": b['doc_count']} 
                for b in result['aggregations']['geographic_threats']['buckets']
            ]
            
            analytics['attack_methods'] = [
                {"method": b['key'], "count": b['doc_count']} 
                for b in result['aggregations']['attack_methods']['buckets']
            ]
            
            return analytics
            
        except Exception as e:
            self.logger.error(f"❌ Analytics failed: {e}")
            return {}
    
    def get_real_time_threats(self, minutes: int = 5) -> List[Dict]:
        """Get recent high-priority threats"""
        if not self.es:
            return []
        
        try:
            time_threshold = datetime.now() - timedelta(minutes=minutes)
            
            s = Search(using=self.es, index="siem-events")
            s = s.filter("range", timestamp={"gte": time_threshold.isoformat()})
            s = s.filter("terms", threat_level=["high", "critical"])
            s = s.sort("-timestamp")
            
            response = s[:50].execute()
            return [hit.to_dict() for hit in response]
            
        except Exception as e:
            self.logger.error(f"❌ Real-time threat query failed: {e}")
            return []
    
    def _analyze_threat_level(self, event: Dict) -> str:
        """Analyze and assign threat level to events"""
        code = event.get('code', event.get('status_code', 200))
        ip = event.get('ip', '')
        url = event.get('url', event.get('req', ''))
        
        # Critical threats
        if code in [500, 502, 503]:
            return "critical"
        
        # High threats
        if code in [401, 403, 404] and any(x in url.lower() for x in ['admin', 'login', 'password', 'user']):
            return "high"
        
        # Medium threats
        if code in [401, 403, 404]:
            return "medium"
        
        # Low threats
        if code in [400, 405]:
            return "low"
        
        return "info"
    
    def _classify_event_type(self, event: Dict) -> str:
        """Classify the type of security event"""
        url = event.get('url', event.get('req', '')).lower()
        code = event.get('code', event.get('status_code', 200))
        
        if 'login' in url or 'auth' in url:
            return "authentication"
        elif 'admin' in url:
            return "privilege_escalation"
        elif code >= 500:
            return "system_error"
        elif code in [401, 403]:
            return "access_denied"
        elif 'api' in url:
            return "api_access"
        else:
            return "web_access"
    
    def _generate_session_id(self) -> str:
        """Generate session ID for activity tracking"""
        import uuid
        return str(uuid.uuid4())[:8]
    
    def get_elasticsearch_status(self) -> Dict[str, Any]:
        """Get Elasticsearch cluster status"""
        if not self.es:
            return {"status": "disconnected", "available": False}
        
        try:
            health = self.es.cluster.health()
            stats = self.es.cluster.stats()
            
            return {
                "status": health['status'],
                "available": True,
                "cluster_name": health['cluster_name'],
                "nodes": health['number_of_nodes'],
                "indices": health['active_primary_shards'],
                "documents": stats['indices']['docs']['count'],
                "storage_size": stats['indices']['store']['size_in_bytes']
            }
        except Exception as e:
            return {"status": "error", "available": False, "error": str(e)}

# Global ELK instance
elk_storage = ELKStorage()