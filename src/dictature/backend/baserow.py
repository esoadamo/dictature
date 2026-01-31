from typing import Iterable, Optional, Dict, Any

try:
    import requests
except ImportError:
    raise ImportError('Requires: pip install requests') from None

from .mock import DictatureBackendMock, DictatureTableMock, Value


class DictatureBackendBaserowSingleTable(DictatureBackendMock):
    def __init__(
            self,
            token: str,
            table_id: int,
            base_url: str = 'https://api.baserow.io'
    ) -> None:
        """
        Create a new Baserow backend using a single table
        :param token: Baserow API token
        :param table_id: Baserow table ID (the table must have 'table', 'key', 'value', 'mode' fields)
        :param base_url: Baserow API base URL
        """
        self.__base_url = base_url.rstrip('/')
        self.__table_id = table_id
        self.__headers = {
            'Authorization': f'Token {token}'
        }

    def keys(self) -> Iterable[str]:
        """Return all table names."""
        # Get distinct table names using pagination
        seen_tables = set()
        url = f"/api/database/rows/table/{self.__table_id}/"
        params = {'user_field_names': 'true', 'size': 200}
        
        while url:
            data = self._request('GET', url, params=params)
            for row in data.get('results', []):
                table = row.get('table')
                if table and table not in seen_tables:
                    seen_tables.add(table)
                    yield table
            url = data.get('next')
            params = None

    def table(self, name: str) -> 'DictatureTableMock':
        return DictatureTableBaserowSingleTable(self, name)

    def _request(self, method: str, url: str, params: Optional[Dict[str, Any]] = None,
                 json: Optional[Dict[str, Any]] = None) -> Any:
        full_url = f"{self.__base_url}{url}"
        response = requests.request(method, full_url, params=params, json=json, headers=self.__headers)
        if not response.ok:
            raise RuntimeError(f"Baserow API error {response.status_code}: {response.text}")
        if response.status_code == 204:
            return None
        return response.json()

    def _table_id(self) -> int:
        return self.__table_id


class DictatureTableBaserowSingleTable(DictatureTableMock):
    def __init__(self, parent: DictatureBackendBaserowSingleTable, table_name: str) -> None:
        self.__parent = parent
        self.__table_name = table_name

    def keys(self) -> Iterable[str]:
        """Return all keys in this table."""
        table_id = self.__parent._table_id()
        
        # Use filter to only get rows for this table
        url = f"/api/database/rows/table/{table_id}/"
        params = {
            'user_field_names': 'true',
            'filter__table__equal': self.__table_name,
            'size': 200
        }
        
        while url:
            data = self.__parent._request('GET', url, params=params)
            for row in data.get('results', []):
                key = row.get('key')
                if key:
                    yield str(key)
            url = data.get('next')
            params = None

    def drop(self) -> None:
        """Delete all rows for this table."""
        table_id = self.__parent._table_id()
        
        # Get all row IDs for this table
        url = f"/api/database/rows/table/{table_id}/"
        params = {
            'user_field_names': 'true',
            'filter__table__equal': self.__table_name,
            'size': 200
        }
        
        rows_to_delete = []
        while url:
            data = self.__parent._request('GET', url, params=params)
            for row in data.get('results', []):
                rows_to_delete.append(row['id'])
            url = data.get('next')
            params = None
        
        # Delete all rows
        for row_id in rows_to_delete:
            try:
                self.__parent._request('DELETE', f"/api/database/rows/table/{table_id}/{row_id}/")
            except RuntimeError:
                pass

    def create(self) -> None:
        """Ensure the backend table exists (already handled by parent)."""
        self.__parent._table_id()

    def set(self, item: str, value: Value) -> None:
        """Set a value for a key in this table."""
        table_id = self.__parent._table_id()
        
        # Try to find existing row using table and key filters
        row = self.__find_row(item)
        
        payload = {
            'table': self.__table_name,
            'key': item,
            'value': value.value,
            'mode': value.mode
        }
        
        if row is not None:
            # Update existing row
            self.__parent._request(
                'PATCH',
                f"/api/database/rows/table/{table_id}/{row['id']}/",
                params={'user_field_names': 'true'},
                json=payload
            )
        else:
            # Create new row
            self.__parent._request(
                'POST',
                f"/api/database/rows/table/{table_id}/",
                params={'user_field_names': 'true'},
                json=payload
            )

    def get(self, item: str) -> Value:
        """Get a value for a key in this table."""
        row = self.__find_row(item)
        if row is None:
            raise KeyError(item)
        
        value = row.get('value')
        mode = row.get('mode')
        return Value(value='' if value is None else str(value), mode=int(mode or 0))

    def delete(self, item: str) -> None:
        """Delete a key from this table."""
        table_id = self.__parent._table_id()
        
        row = self.__find_row(item)
        if row is None:
            return
        
        self.__parent._request('DELETE', f"/api/database/rows/table/{table_id}/{row['id']}/")

    def __find_row(self, item: str) -> Optional[Dict[str, Any]]:
        """Find a row by table and key using backend filters."""
        table_id = self.__parent._table_id()
        
        data = self.__parent._request(
            'GET',
            f"/api/database/rows/table/{table_id}/",
            params={
                'user_field_names': 'true',
                'filter__table__equal': self.__table_name,
                'filter__key__equal': item,
                'size': 1
            }
        )
        results = data.get('results', [])
        return results[0] if results else None
