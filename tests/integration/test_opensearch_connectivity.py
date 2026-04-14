# OpenSearch Connectivity Test
# Version: v0.1.2
# Timestamp: 2026-04-07

"""
Integration test for OpenSearch connectivity.
Tests the OpenSearch client initialization, connection, and basic operations.
"""

import os
import sys
import logging
from unittest.mock import Mock, patch, MagicMock

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

from utils.opensearch_client import OpenSearchClient

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_opensearch_client_initialization():
    """Test OpenSearch client initialization."""
    client = OpenSearchClient()
    
    assert client.host == os.getenv('OPENSEARCH_HOST', '10.0.0.50')
    assert client.port == int(os.getenv('OPENSEARCH_PORT', '9200'))
    assert client.user == os.getenv('OPENSEARCH_USER', 'admin')
    assert client.index_default == os.getenv('OPENSEARCH_INDEX', 'chat_history')
    assert client.index_playbook == os.getenv('OPENSEARCH_INDEX_PLAYBOOK', 'chat_history')
    assert client.index_cve == os.getenv('OPENSEARCH_INDEX_CVE', 'cve')
    assert client.index_vector == os.getenv('OPENSEARCH_INDEX_VECTOR', 'spring-ai-document-index')
    assert client.index_qa_results == os.getenv('OPENSEARCH_INDEX_QA_RESULTS', 'playbook_qa_results-000001')
    
    logger.info("OpenSearch client initialization test passed")


def test_opensearch_ping():
    """Test OpenSearch ping functionality."""
    client = OpenSearchClient()
    
    # Mock the ping method
    with patch.object(client.client, 'ping', return_value=True):
        result = client.ping()
        assert result is True
    
    logger.info("OpenSearch ping test passed")


def test_opensearch_search():
    """Test OpenSearch search functionality."""
    client = OpenSearchClient()
    
    # Mock search response
    mock_response = {
        'hits': {
            'hits': [
                {'_id': '1', '_source': {'test': 'data'}}
            ],
            'total': {'value': 1}
        }
    }
    
    with patch.object(client.client, 'search', return_value=mock_response):
        query = {"query": {"match_all": {}}}
        result = client.search('test_index', query, size=10)
        
        assert 'hits' in result
        assert len(result['hits']['hits']) == 1
        assert result['hits']['hits'][0]['_id'] == '1'
    
    logger.info("OpenSearch search test passed")


def test_get_all_playbooks():
    """Test get_all_playbooks functionality."""
    client = OpenSearchClient()
    
    # Mock search response with playbooks
    mock_response = {
        'hits': {
            'hits': [
                {
                    '_id': '1',
                    '_source': {
                        'is_play_book': True,
                        'title': 'Test Playbook',
                        'timestamp': '2024-01-01T00:00:00Z'
                    }
                }
            ],
            'total': {'value': 1}
        }
    }
    
    with patch.object(client.client, 'search', return_value=mock_response):
        result = client.get_all_playbooks(size=100)
        
        assert 'hits' in result
        assert len(result['hits']['hits']) == 1
        playbook = result['hits']['hits'][0]['_source']
        assert playbook['is_play_book'] is True
        assert playbook['title'] == 'Test Playbook'
    
    logger.info("Get all playbooks test passed")


def test_get_cve():
    """Test get_cve functionality."""
    client = OpenSearchClient()
    
    # Mock search response for CVE
    mock_response = {
        'hits': {
            'hits': [
                {
                    '_id': 'CVE-2021-44228',
                    '_source': {
                        'cve_id': 'CVE-2021-44228',
                        'description': 'Log4j vulnerability',
                        'severity': 'CRITICAL'
                    }
                }
            ],
            'total': {'value': 1}
        }
    }
    
    with patch.object(client.client, 'search', return_value=mock_response):
        result = client.get_cve('CVE-2021-44228')
        
        assert '_id' in result
        assert result['_id'] == 'CVE-2021-44228'
        assert result['_source']['cve_id'] == 'CVE-2021-44228'
        assert result['_source']['severity'] == 'CRITICAL'
    
    logger.info("Get CVE test passed")


def test_scroll_search():
    """Test scroll search functionality."""
    client = OpenSearchClient()
    
    # Mock scroll search responses
    mock_first_response = {
        '_scroll_id': 'scroll_123',
        'hits': {
            'hits': [
                {'_id': '1', '_source': {'data': 'first'}}
            ]
        }
    }
    
    mock_second_response = {
        '_scroll_id': 'scroll_123',
        'hits': {
            'hits': [
                {'_id': '2', '_source': {'data': 'second'}}
            ]
        }
    }
    
    mock_empty_response = {
        '_scroll_id': 'scroll_123',
        'hits': {
            'hits': []
        }
    }
    
    with patch.object(client.client, 'search', return_value=mock_first_response), \
         patch.object(client.client, 'scroll', side_effect=[mock_second_response, mock_empty_response]), \
         patch.object(client.client, 'clear_scroll'):
        
        query = {"query": {"match_all": {}}}
        results = client.scroll_search('test_index', query)
        
        assert len(results) == 2
        assert results[0]['_id'] == '1'
        assert results[1]['_id'] == '2'
    
    logger.info("Scroll search test passed")


def test_opensearch_close():
    """Test OpenSearch client close functionality."""
    client = OpenSearchClient()
    
    # Mock the close method
    with patch.object(client.client, 'close'):
        client.close()
        # Verify close was called
        client.client.close.assert_called_once()
    
    logger.info("OpenSearch close test passed")


if __name__ == "__main__":
    """Run OpenSearch connectivity tests."""
    print("Running OpenSearch connectivity tests...")
    
    try:
        test_opensearch_client_initialization()
        test_opensearch_ping()
        test_opensearch_search()
        test_get_all_playbooks()
        test_get_cve()
        test_scroll_search()
        test_opensearch_close()
        
        print("All OpenSearch connectivity tests passed!")
    except Exception as e:
        print(f"OpenSearch connectivity tests failed: {e}")
        sys.exit(1)