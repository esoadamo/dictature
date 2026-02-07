"""Confluence backend using Content Properties for atomic KV storage."""
import re
import html
import time
from typing import Iterable, Optional, Dict, Any

try:
    import requests
except ImportError:
    raise ImportError('Requires: pip install requests') from None

from .mock import DictatureBackendMock, DictatureTableMock, Value, ValueSerializer, ValueSerializerMode


class DictatureBackendConfluence(DictatureBackendMock):
    """
    Backend that stores data in Confluence using Content Properties for atomicity.
    
    Each table is a child page under the root page. Key-value pairs are stored
    as Content Properties on the page resource.
    
    This allows atomic updates of individual keys.
    """

    def __init__(
            self,
            base_url: str,
            username: str,
            api_token: str,
            root_page_id: str,
            sync_page_content: bool = False,
    ) -> None:
        """
        Create a new Confluence backend.
        
        :param base_url: Confluence base URL (e.g., 'https://yoursite.atlassian.net/wiki')
        :param username: Atlassian account email/username
        :param api_token: Atlassian API token
        :param root_page_id: ID of the root page under which table pages will be created
        :param sync_page_content: If True, also update the page body with a table of all properties (slower)
        """
        self.__base_url = base_url.rstrip('/')
        self.__root_page_id = root_page_id
        self.__sync_page_content = sync_page_content
        self.__session = requests.Session()
        self.__session.auth = (username, api_token)
        self.__session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        })
        # Cache the space key from root page
        self.__space_key: Optional[str] = None

    def _get_space_key(self) -> str:
        """Get the space key from the root page (cached)."""
        if self.__space_key is None:
            page = self._request('GET', f'/rest/api/content/{self.__root_page_id}', params={'expand': 'space'})
            self.__space_key = page['space']['key']
        return self.__space_key

    def keys(self) -> Iterable[str]:
        """Return all table names (child page titles under root page)."""
        url = f'/rest/api/content/{self.__root_page_id}/child/page'
        params = {'limit': 100}
        
        while url:
            data = self._request('GET', url, params=params)
            for page in data.get('results', []):
                yield page['title']
            
            # Handle pagination
            next_link = data.get('_links', {}).get('next')
            if next_link:
                url = next_link
                params = None
            else:
                url = None

    def table(self, name: str) -> 'DictatureTableConfluence':
        return DictatureTableConfluence(self, name, self.__sync_page_content)

    def _request(self, method: str, url: str, params: Optional[Dict[str, Any]] = None,
                 json: Optional[Dict[str, Any]] = None) -> Any:
        """Make an API request to Confluence."""
        if url.startswith('http://') or url.startswith('https://'):
            full_url = url
        else:
            full_url = f"{self.__base_url}{url}"
        
        response = self.__session.request(method, full_url, params=params, json=json)
        
        # Handle 404 (Not Found) gracefully if needed by caller, otherwise raise
        if response.status_code == 404:
            return None
            
        if not response.ok:
            # Pass through 409 Conflict for retry logic handling
            if response.status_code == 409:
                response.raise_for_status() 
            raise RuntimeError(f"Confluence API error {response.status_code}: {response.text}")
            
        if response.status_code == 204:
            return None
        
        try:
            return response.json()
        except ValueError:
            return None

    def _get_root_page_id(self) -> str:
        return self.__root_page_id


class DictatureTableConfluence(DictatureTableMock):
    """A table stored as a Confluence page using Content Properties."""

    MAX_RETRIES = 5

    def __init__(self, parent: DictatureBackendConfluence, table_name: str, sync_page_content: bool) -> None:
        self.__parent = parent
        self.__table_name = table_name
        self.__sync_page_content = sync_page_content
        self.__serializer = ValueSerializer(mode=ValueSerializerMode.any_string)

    def _find_page_id(self) -> Optional[str]:
        """Find the page ID for this table by title."""
        root_id = self.__parent._get_root_page_id()
        url = f'/rest/api/content/{root_id}/child/page'
        params = {'limit': 100}
        
        while url:
            data = self.__parent._request('GET', url, params=params)
            if not data:
                return None
                
            for page in data.get('results', []):
                if page['title'] == self.__table_name:
                    return page['id']
            
            next_link = data.get('_links', {}).get('next')
            if next_link:
                url = next_link
                params = None
            else:
                url = None
        
        return None

    def _encode_key(self, key: str) -> str:
        """Hex encode the key to meet content property key constraints."""
        return key.encode('utf-8').hex()

    def _decode_key(self, hex_key: str) -> str:
        """Decode hex key back to string."""
        return bytes.fromhex(hex_key).decode('utf-8')

    def create(self) -> str:
        """Create the table page if it doesn't exist, return page ID."""
        page_id = self._find_page_id()
        if page_id is not None:
            return page_id
        
        space_key = self.__parent._get_space_key()
        root_id = self.__parent._get_root_page_id()
        
        payload = {
            'type': 'page',
            'title': self.__table_name,
            'space': {'key': space_key},
            'ancestors': [{'id': root_id}],
            'body': {
                'storage': {
                    'value': '<p>This page acts as a key-value store database table.</p>',
                    'representation': 'storage',
                }
            }
        }
        
        try:
            data = self.__parent._request('POST', '/rest/api/content', json=payload)
            return data['id']
        except RuntimeError as e:
            # Handle race condition where page might be created by another process
            if "already exists" in str(e) or "400" in str(e): # Confluence often returns 400 for duplicate title
                 page_id = self._find_page_id()
                 if page_id:
                     return page_id
            raise e

    def keys(self) -> Iterable[str]:
        """Return all keys in this table (from content properties)."""
        page_id = self._find_page_id()
        if page_id is None:
            return
            
        url = f'/rest/api/content/{page_id}/property'
        params = {'limit': 100}
        
        while url:
            data = self.__parent._request('GET', url, params=params)
            if not data:
                break
                
            for prop in data.get('results', []):
                hex_key = prop['key']
                # Check if it's our property (we assume all properties on this page are ours)
                # But we should be careful about other plugins. 
                # Our keys are hex strings, so we can try to decode.
                try:
                    yield self._decode_key(hex_key)
                except ValueError:
                    pass # Ignore properties that aren't hex encoded (not ours)
            
            next_link = data.get('_links', {}).get('next')
            if next_link:
                url = next_link
                params = None
            else:
                url = None

    def set(self, item: str, value: Value) -> None:
        """Set a value for a key as a content property."""
        page_id = self.create()
        hex_key = self._encode_key(item)
        serialized = self.__serializer.serialize(value)
        
        self.__set_property(page_id, hex_key, serialized, value.mode, item)
        
        if self.__sync_page_content:
            self.__sync_content(page_id)

    def __set_property(self, page_id: str, hex_key: str, serialized_value: str, mode: int, original_key: str) -> None:
        """Set content property with optimistic locking for the property resource."""
        property_data = {
            "key": original_key,
            "value": serialized_value,
            "mode": mode
        }
        
        # Retry loop for property update
        for attempt in range(self.MAX_RETRIES):
            # 1. Try to get existing property to know version
            prop = self.__parent._request('GET', f'/rest/api/content/{page_id}/property/{hex_key}')
            
            if prop:
                # Update existing
                version = prop['version']['number'] + 1
                prop_id = prop['id']
                url = f'/rest/api/content/{page_id}/property/{hex_key}'
                payload = {
                    'version': {'number': version},
                    'value': property_data
                }
                method = 'PUT'
            else:
                # Create new
                url = f'/rest/api/content/{page_id}/property'
                payload = {
                    'key': hex_key,
                    'value': property_data
                }
                method = 'POST'
            
            try:
                self.__parent._request(method, url, json=payload)
                return # Success
            except requests.exceptions.HTTPError as e: # requests raises HTTPError for 409 if we use raise_for_status
                if e.response.status_code == 409:
                    time.sleep(0.1 * (attempt + 1)) # Backoff
                    continue # Retry
                raise e
            except RuntimeError as e:
                 # Check if our custom wrapper raised it (though we pass 409)
                 if "409" in str(e):
                      time.sleep(0.1 * (attempt + 1))
                      continue
                 raise e

        raise RuntimeError(f"Failed to set property '{original_key}' after {self.MAX_RETRIES} attempts due to conflicts.")

    def get(self, item: str) -> Value:
        """Get a value for a key."""
        page_id = self._find_page_id()
        if page_id is None:
            raise KeyError(item)
        
        hex_key = self._encode_key(item)
        prop = self.__parent._request('GET', f'/rest/api/content/{page_id}/property/{hex_key}')
        
        if not prop:
            raise KeyError(item)
            
        value_data = prop['value']
        # Migration: Check if value is new dict format or old simple structure (if any)
        # We enforce dict format now.
        if isinstance(value_data, dict) and 'value' in value_data and 'mode' in value_data:
            return self.__serializer.deserialize(value_data['value'])
        else:
             # Just in case some other data got there
             raise ValueError(f"Invalid property format for key {item}")

    def delete(self, item: str) -> None:
        """Delete a key."""
        page_id = self._find_page_id()
        if page_id is None:
            return
            
        hex_key = self._encode_key(item)
        
        # Check if exists
        prop = self.__parent._request('GET', f'/rest/api/content/{page_id}/property/{hex_key}')
        if not prop:
            return
            
        try:
            self.__parent._request('DELETE', f'/rest/api/content/{page_id}/property/{hex_key}')
        except RuntimeError:
            pass # Already deleted or error
            
        if self.__sync_page_content:
            self.__sync_content(page_id)

    def drop(self) -> None:
        """Delete the table page."""
        page_id = self._find_page_id()
        if page_id is None:
            return
        self.__parent._request('DELETE', f'/rest/api/content/{page_id}')

    def __sync_content(self, page_id: str) -> None:
        """Update page body to list all properties (Best effort)."""
        try:
            # 1. Fetch all properties with values efficiently
            all_props = {}
            url = f'/rest/api/content/{page_id}/property'
            params = {'limit': 100, 'expand': 'value'}
            
            while url:
                data = self.__parent._request('GET', url, params=params)
                if not data:
                    break
                    
                for prop in data.get('results', []):
                    hex_key = prop['key']
                    try:
                        key = self._decode_key(hex_key)
                        value_data = prop.get('value', {})
                        # Handle value format
                        if isinstance(value_data, dict) and 'value' in value_data:
                            val_str = str(value_data['value'])
                            all_props[key] = val_str
                        else:
                            all_props[key] = str(value_data)
                    except ValueError:
                        pass # Not our property
                
                next_link = data.get('_links', {}).get('next')
                if next_link:
                    url = next_link
                    params = None
                else:
                    url = None

            # 2. Build HTML
            rows = []
            for key, val_str in sorted(all_props.items()):
                if len(val_str) > 100: val_str = val_str[:97] + "..."
                rows.append(f'<tr><th>{html.escape(key)}</th><td>{html.escape(val_str)}</td></tr>')
            
            rows_html = '\n'.join(rows)
            new_content = f'''<p><strong>Content Properties (read-only, do not edit)</strong></p>
<table>
<colgroup><col /><col /></colgroup>
<tbody>
{rows_html}
</tbody>
</table>'''

            # 3. Update page with optimistic locking
            for attempt in range(self.MAX_RETRIES):
                try:
                    page = self.__parent._request('GET', f'/rest/api/content/{page_id}', params={'expand': 'version'})
                    version = page['version']['number'] + 1
                    
                    payload = {
                        'version': {'number': version},
                        'type': 'page',
                        'title': page['title'],
                        'body': {
                            'storage': {
                                'value': new_content,
                                'representation': 'storage',
                            }
                        }
                    }
                
                    self.__parent._request('PUT', f'/rest/api/content/{page_id}', json=payload)
                    return
                except (RuntimeError, requests.exceptions.HTTPError) as e:
                    if "409" in str(e) or (hasattr(e, 'response') and e.response.status_code == 409):
                        time.sleep(0.1 * (attempt+1))
                        continue
                    # Only log warning if sync fails, don't crash main operation
                    print(f"Warning: Sync page update failed (attempt {attempt}): {e}")
        except Exception as e:
            # Sync is optional, log but don't fail the operation
            print(f"Warning: Failed to sync page content: {e}")

