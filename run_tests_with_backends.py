#!/usr/bin/env python3
"""
Launch self-hostable backends and run tests.

This script:
1. Starts backend services using docker-compose
2. Waits for services to be healthy
3. Sets up environment variables and credentials
4. Runs the test suite
5. Cleans up services on exit
"""

import os
import sys
import time
import subprocess
import signal
import argparse
import re
from typing import Dict, List, Optional, Tuple
import requests

# Colors for output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
RESET = '\033[0m'


def log_info(message: str) -> None:
    """Print an info message in green."""
    print(f"{GREEN}[INFO]{RESET} {message}")


def log_warning(message: str) -> None:
    """Print a warning message in yellow."""
    print(f"{YELLOW}[WARNING]{RESET} {message}")


def log_error(message: str) -> None:
    """Print an error message in red."""
    print(f"{RED}[ERROR]{RESET} {message}")


def run_command(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
    """
    Run a shell command and return the result.
    
    Args:
        cmd: Command and arguments as a list
        check: Whether to raise an exception on non-zero exit code
        
    Returns:
        CompletedProcess instance with command results
    """
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=check)
    except subprocess.CalledProcessError as e:
        log_error(f"Command failed: {' '.join(cmd)}")
        log_error(f"stdout: {e.stdout}")
        log_error(f"stderr: {e.stderr}")
        raise


def start_services(docker_compose_file: str = 'dictature-test-backends-compose.yml', enabled_backends: Dict[str, bool] = None) -> None:
    """
    Start enabled backend services and stop disabled ones.
    
    Args:
        docker_compose_file: Path to docker-compose configuration file
        enabled_backends: Dictionary mapping backend names to enabled status
    """
    log_info("Starting backend services...")
    
    if not os.path.exists(docker_compose_file):
        log_error(f"docker-compose file not found: {docker_compose_file}")
        sys.exit(1)
    
    # Start all services first
    run_command(['podman-compose', '-f', docker_compose_file, 'up', '-d'])
    
    # Determine which services to keep based on enabled backends
    if enabled_backends:
        # Map backend names to container names and their dependencies
        backend_to_services = {
            'mysql': ['dictature-mysql'],
            's3': ['dictature-rclone-s3'],
            'webdav': ['dictature-rclone-webdav'],
            'misp': ['dictature-misp', 'dictature-mysql', 'dictature-redis'],  # MISP depends on MySQL and Redis
            'baserow': ['dictature-baserow'],
        }
        
        # Collect all needed services
        needed_services = set()
        for backend, enabled in enabled_backends.items():
            if enabled and backend in backend_to_services:
                needed_services.update(backend_to_services[backend])
        
        # All possible services
        all_services = ['dictature-mysql', 'dictature-rclone-s3', 'dictature-rclone-webdav', 
                       'dictature-misp', 'dictature-baserow', 'dictature-redis']
        
        # Stop services that are not needed
        services_to_stop = set(all_services) - needed_services
        for service in services_to_stop:
            log_info(f"Stopping disabled service: {service}")
            run_command(['podman', 'stop', service], check=False)
            run_command(['podman', 'rm', '-f', service], check=False)
    
    log_info("Services started. Waiting for health checks...")


def wait_for_services(enabled_backends: Optional[Dict[str, bool]] = None, timeout: int = 360) -> None:
    """
    Wait for enabled backend services to become healthy.
    
    Args:
        enabled_backends: Dictionary mapping backend names to enabled status
        timeout: Maximum seconds to wait for each service
    """
    # Map backend names to container names that need health checks
    backend_to_services = {
        'mysql': ['dictature-mysql'],
        's3': ['dictature-rclone-s3'],
        'webdav': ['dictature-rclone-webdav'],
        'misp': ['dictature-misp', 'dictature-mysql', 'dictature-redis'],
        'baserow': ['dictature-baserow'],
    }
    
    # Determine which services to wait for
    services = set()
    if enabled_backends:
        for backend, enabled in enabled_backends.items():
            if enabled and backend in backend_to_services:
                services.update(backend_to_services[backend])
    else:
        # Default: wait for all basic services
        services = {'dictature-mysql', 'dictature-rclone-s3', 'dictature-rclone-webdav'}
    
    if not services:
        log_info("No backend services to wait for")
        return
    
    log_info(f"Waiting for services: {', '.join(sorted(services))}")
    start_time = time.time()
    
    for service in sorted(services):
        while time.time() - start_time < timeout:
            result = run_command(
                ['podman', 'inspect', '-f', '{{.State.Health.Status}}', service],
                check=False
            )
            
            if result.returncode == 0:
                if 'healthy' in result.stdout:
                    log_info(f"✓ {service} is healthy")
                    break
                elif 'unhealthy' in result.stdout:
                    log_warning(f"Service {service} is unhealthy, retrying...")
            
            time.sleep(5)
        else:
            log_warning(f"Timeout waiting for {service} to become healthy")


def setup_environment_variables(enabled_backends: Dict[str, bool]) -> None:
    """
    Configure environment variables for enabled backends.
    
    Args:
        enabled_backends: Dictionary mapping backend names to enabled status
    """
    env_vars = {}
    
    if enabled_backends.get('mysql', True):
        env_vars.update({
            'MYSQL_HOST': 'localhost',
            'MYSQL_USER': 'dictature',
            'MYSQL_PASSWORD': 'password123',
            'MYSQL_DATABASE': 'dictature',
            'MYSQL_PORT': '33060',
        })
    
    if enabled_backends.get('s3', True):
        env_vars.update({
            'S3_BUCKET': 'dictature',
            'AWS_ACCESS_KEY_ID': 'admin',
            'AWS_SECRET_ACCESS_KEY': 'password123',
            'S3_ENDPOINT_URL': 'http://localhost:49000',
            'AWS_REGION': 'us-east-1',
        })
    
    if enabled_backends.get('webdav', True):
        env_vars.update({
            'WEBDAV_URL': 'http://localhost:48080',
            'WEBDAV_LOGIN': 'admin',
            'WEBDAV_PASSWORD': 'password123',
        })
    
    if enabled_backends.get('misp', True):
        env_vars['MISP_URL'] = 'http://localhost:8888'

    if enabled_backends.get('baserow', True):
        os.environ['BASEROW_URL'] = 'http://localhost:3001'

    # Set all environment variables
    for key, value in env_vars.items():
        os.environ[key] = value
    
    # Log configuration (hide sensitive values)
    log_info("Environment variables configured:")
    for key, value in env_vars.items():
        display_value = '***' if any(x in key for x in ['PASSWORD', 'KEY', 'TOKEN']) else value
        print(f"  {key}={display_value}")


def create_s3_bucket() -> None:
    """Create S3 bucket directory structure in rclone container."""
    log_info("Setting up S3 bucket in rclone...")
    try:
        run_command([
            'podman', 'exec', 'dictature-rclone-s3',
            'mkdir', '-p', '/data/dictature'
        ], check=False)
        log_info("✓ S3 bucket structure created")
    except Exception as e:
        log_warning(f"Could not create S3 bucket structure: {e}")


def stop_services(docker_compose_file: str = 'dictature-test-backends-compose.yml') -> None:
    """
    Stop and remove all backend services.
    
    Args:
        docker_compose_file: Path to docker-compose configuration file
    """
    log_info("Stopping backend services...")
    run_command(['podman-compose', '-f', docker_compose_file, 'down', '-v'], check=False)
    log_info("Services stopped")


def run_tests(test_dir: str = 'tests') -> bool:
    """
    Run the test suite using pytest.
    
    Args:
        test_dir: Directory containing test files
        
    Returns:
        True if all tests passed, False otherwise
    """
    log_info("Running tests...")
    cmd = [sys.executable, '-m', 'pytest', f'{test_dir}/test_operations.py', '-v']
    
    result = subprocess.run(cmd)
    return result.returncode == 0


def wait_for_http(url: str, timeout: int = 180) -> bool:
    """
    Wait for an HTTP endpoint to become available.
    
    Args:
        url: URL to check
        timeout: Maximum seconds to wait
        
    Returns:
        True if endpoint is available, False if timeout reached
    """
    log_info(f"Waiting for {url} to be available...")
    start = time.time()
    
    while time.time() - start < timeout:
        try:
            r = requests.get(url, timeout=5)
            if r.status_code < 500:
                log_info(f"✓ {url} is up")
                return True
        except Exception:
            pass
        time.sleep(3)
    
    log_error(f"Timeout waiting for {url}")
    return False


def extract_csrf_tokens(html: str) -> Dict[str, str]:
    """
    Extract CSRF tokens from MISP HTML page.
    
    Args:
        html: HTML page content
        
    Returns:
        Dictionary of token names to values
    """
    csrf_patterns = [
        (r'name="data\[_Token\]\[key\]"\s+value="([^"]+)"', 'key'),
        (r'name="data\[_Token\]\[fields\]"\s+value="([^"]+)"', 'fields'),
        (r'name="data\[_Token\]\[unlocked\]"\s+value="([^"]*)"', 'unlocked'),
    ]
    
    tokens = {}
    for pattern, name in csrf_patterns:
        match = re.search(pattern, html)
        if match:
            tokens[name] = match.group(1)
    
    return tokens


def extract_misp_api_key(html: str) -> Optional[str]:
    """
    Extract MISP API key from user profile HTML.
    
    Args:
        html: HTML page content
        
    Returns:
        40-character API key if found, None otherwise
    """
    authkey_patterns = [
        r'<dd[^>]*>\s*([a-zA-Z0-9]{40})\s*</dd>',
        r'authkey["\s:>]+([a-zA-Z0-9]{40})',
        r'value="([a-zA-Z0-9]{40})"',
    ]
    
    for pattern in authkey_patterns:
        matches = re.findall(pattern, html)
        for match in matches:
            if len(match) == 40 and match.isalnum():
                return match
    
    return None


def misp_register_and_get_key() -> Optional[str]:
    """
    Authenticate with MISP and retrieve API key.
    
    Attempts to log in with default credentials, change the expired password,
    and extract the API key from the user profile.
    
    Returns:
        API key string if successful, None otherwise
    """
    url = "http://localhost:8888"
    wait_for_http(url)
    
    try:
        from pymisp import PyMISP
    except ImportError:
        log_error("pymisp package not installed. Install with: pip install pymisp")
        return None
    
    try:
        default_email = "admin@admin.test"
        default_password = "admin"
        new_password = "NewSecurePassword123!"
        
        log_info(f"Authenticating with MISP as {default_email}")
        
        session = requests.Session()
        session.verify = False
        
        # Get login page and extract CSRF tokens
        log_info("Getting login page...")
        login_page = session.get(f"{url}/users/login")
        csrf_tokens = extract_csrf_tokens(login_page.text)
        
        if not csrf_tokens:
            log_warning("Could not find CSRF tokens in login page")
        
        # Login with default credentials
        log_info("Logging in...")
        login_data = {
            'data[User][email]': default_email,
            'data[User][password]': default_password,
        }
        for key in ['key', 'fields', 'unlocked']:
            if key in csrf_tokens:
                login_data[f'data[_Token][{key}]'] = csrf_tokens[key]
        
        login_response = session.post(
            f"{url}/users/login",
            data=login_data,
            allow_redirects=True
        )
        
        # Change password if required
        if '/users/change_pw' in login_response.url or 'change_pw' in login_response.text:
            log_info("Password change required, updating password...")
            
            change_pw_page = session.get(f"{url}/users/change_pw")
            csrf_tokens = extract_csrf_tokens(change_pw_page.text)
            
            change_pw_data = {
                'data[User][current_password]': default_password,
                'data[User][password]': new_password,
                'data[User][confirm_password]': new_password,
            }
            for key in ['key', 'fields', 'unlocked']:
                if key in csrf_tokens:
                    change_pw_data[f'data[_Token][{key}]'] = csrf_tokens[key]
            
            change_pw_response = session.post(
                f"{url}/users/change_pw",
                data=change_pw_data,
                allow_redirects=True
            )
            
            if change_pw_response.ok:
                log_info("✓ Password changed successfully")
            else:
                log_warning(f"Password change may have failed: HTTP {change_pw_response.status_code}")
        
        # Get API key from profile
        log_info("Retrieving API key from user profile...")
        profile_response = session.get(f"{url}/users/view/me")
        
        if not profile_response.ok:
            log_warning(f"Failed to get profile page: HTTP {profile_response.status_code}")
            return None
        
        api_key = extract_misp_api_key(profile_response.text)
        
        if not api_key:
            log_warning("Could not find API key in profile page")
            return None
        
        log_info(f"✓ Successfully obtained MISP API key: {api_key[:8]}...")
        
        # Verify the key works
        misp_verify = PyMISP(url, api_key, ssl=False)
        verify_user = misp_verify.get_user('me')
        
        if 'User' in verify_user:
            log_info("✓ API key verified successfully")
            log_info(f"✓ User: {verify_user['User'].get('email', 'unknown')}") # type: ignore
            return api_key
        
        log_warning("API key verification failed")
        return None
        
    except Exception as e:
        log_warning(f"Error obtaining MISP API key: {e}")
        return None


def baserow_register_and_get_token() -> Optional[Tuple[str, int]]:
    """
    Register/login to Baserow and setup workspace with API token.
    
    Creates a workspace, database, table with required fields, and generates
    an API token for authentication.
    
    Returns:
        Tuple of (API token, table ID) if successful, None otherwise
    """
    base_url = "http://localhost:3001"
    wait_for_http(base_url)
    
    admin_email = "admin@example.com"
    admin_password = "password123"
    admin_name = "Admin User"
    
    try:
        # Register or login
        jwt_token = _baserow_authenticate(base_url, admin_email, admin_password, admin_name)
        if not jwt_token:
            return None
        
        headers = {"Authorization": f"JWT {jwt_token}"}
        
        # Get or create workspace
        workspace_id = _baserow_get_workspace(base_url, headers)
        if not workspace_id:
            return None
        
        # Get or create database
        db_id = _baserow_get_database(base_url, headers, workspace_id)
        if not db_id:
            return None
        
        # Get or create table
        table_id = _baserow_get_table(base_url, headers, db_id)
        if not table_id:
            return None
        
        # Setup table fields
        _baserow_setup_fields(base_url, headers, table_id)
        
        # Create API token
        api_key = _baserow_create_token(base_url, headers, workspace_id)
        if not api_key:
            return None
        
        return api_key, table_id
        
    except Exception as e:
        log_warning(f"Error during Baserow setup: {e}")
        return None


def _baserow_authenticate(base_url: str, email: str, password: str, name: str) -> Optional[str]:
    """Authenticate with Baserow and return JWT token."""
    register_data = {
        "name": name,
        "email": email,
        "password": password,
        "authenticate": True
    }
    
    try:
        r = requests.post(f"{base_url}/api/user/", json=register_data, timeout=10)
        if r.status_code == 200:
            data = r.json()
            jwt_token = data.get('access_token') or data.get('token')
            log_info("Successfully registered admin user.")
            return jwt_token
        elif r.status_code == 400 and ("email" in r.text.lower() or "already_exists" in r.text):
            # User exists, try login
            log_info("User exists, attempting login...")
            login_data = {"email": email, "password": password}
            login_response = requests.post(
                f"{base_url}/api/user/token-auth/",
                json=login_data,
                timeout=10
            )
            
            if login_response.ok:
                data = login_response.json()
                jwt_token = data.get('access_token') or data.get('token')
                log_info("Successfully logged in.")
                return jwt_token
            
            log_warning(f"Login failed: {login_response.status_code}")
            return None
        
        log_warning(f"Registration failed: {r.status_code} - {r.text[:200]}")
        return None
        
    except Exception as e:
        log_warning(f"Authentication error: {e}")
        return None


def _baserow_get_workspace(base_url: str, headers: Dict[str, str]) -> Optional[int]:
    """Get existing workspace or create new one."""
    try:
        workspaces_response = requests.get(
            f"{base_url}/api/workspaces/",
            headers=headers,
            timeout=10
        )
        
        if not workspaces_response.ok:
            log_warning(f"Could not fetch workspaces: {workspaces_response.status_code}")
            return None
        
        workspaces = workspaces_response.json()
        if workspaces:
            workspace_id = workspaces[0]['id']
            log_info(f"Using existing workspace: {workspace_id}")
            return workspace_id
        
        # Create new workspace
        log_info("Creating new workspace...")
        create_response = requests.post(
            f"{base_url}/api/workspaces/",
            json={"name": "dictature_test_workspace"},
            headers=headers,
            timeout=10
        )
        
        if create_response.ok:
            workspace_id = create_response.json()['id']
            log_info(f"Created workspace: {workspace_id}")
            return workspace_id
        
        log_warning(f"Could not create workspace: {create_response.status_code}")
        return None
        
    except Exception as e:
        log_warning(f"Workspace error: {e}")
        return None


def _baserow_get_database(base_url: str, headers: Dict[str, str], workspace_id: int) -> Optional[int]:
    """Get existing database or create new one."""
    try:
        apps_response = requests.get(
            f"{base_url}/api/applications/workspace/{workspace_id}/",
            headers=headers,
            timeout=10
        )
        
        if not apps_response.ok:
            log_warning(f"Could not fetch applications: {apps_response.status_code}")
            return None
        
        apps = apps_response.json()
        db_app = next((app for app in apps if app.get('type') == 'database'), None)
        
        if db_app:
            db_id = db_app['id']
            log_info(f"Using existing database: {db_id}")
            return db_id
        
        # Create new database
        create_response = requests.post(
            f"{base_url}/api/applications/workspace/{workspace_id}/",
            json={"name": "dictature_test_db", "type": "database"},
            headers=headers,
            timeout=10
        )
        
        if create_response.ok:
            db_id = create_response.json()['id']
            log_info(f"Created database: {db_id}")
            return db_id
        
        log_warning(f"Could not create database: {create_response.status_code}")
        return None
        
    except Exception as e:
        log_warning(f"Database error: {e}")
        return None


def _baserow_get_table(base_url: str, headers: Dict[str, str], db_id: int) -> Optional[int]:
    """Get existing table or create new one."""
    try:
        tables_response = requests.get(
            f"{base_url}/api/database/tables/database/{db_id}/",
            headers=headers,
            timeout=10
        )
        
        if not tables_response.ok:
            log_warning(f"Could not fetch tables: {tables_response.status_code}")
            return None
        
        tables = tables_response.json()
        existing_table = next((t for t in tables if t.get('name') == 'dictature_data'), None)
        
        if existing_table:
            table_id = existing_table['id']
            log_info(f"Using existing table: {table_id}")
            return table_id
        
        # Create new table
        create_response = requests.post(
            f"{base_url}/api/database/tables/database/{db_id}/",
            json={'name': 'dictature_data'},
            headers=headers,
            timeout=10
        )
        
        if create_response.ok:
            table_id = create_response.json()['id']
            log_info(f"Created table: {table_id}")
            return table_id
        
        log_warning(f"Could not create table: {create_response.status_code}")
        return None
        
    except Exception as e:
        log_warning(f"Table error: {e}")
        return None


def _baserow_setup_fields(base_url: str, headers: Dict[str, str], table_id: int) -> None:
    """Setup required fields for the table."""
    try:
        fields_response = requests.get(
            f"{base_url}/api/database/fields/table/{table_id}/",
            headers=headers,
            timeout=10
        )
        
        if not fields_response.ok:
            return
        
        fields = fields_response.json()
        required_fields = {'table', 'key', 'value', 'mode'}
        existing_fields = {f.get('name') for f in fields}
        
        # Delete unnecessary fields
        for field in fields:
            field_name = field.get('name')
            field_id = field.get('id')
            is_primary = field.get('primary')
            
            if field_name not in required_fields and not is_primary:
                requests.delete(
                    f"{base_url}/api/database/fields/{field_id}/",
                    headers=headers,
                    timeout=10
                )
                log_info(f"Deleted field '{field_name}'")
            elif is_primary and field_name not in required_fields:
                requests.patch(
                    f"{base_url}/api/database/fields/{field_id}/",
                    json={'name': 'table'},
                    headers=headers,
                    timeout=10
                )
                log_info(f"Renamed primary field to 'table'")
                existing_fields.add('table')
        
        # Create missing fields
        field_configs = {
            'table': {'name': 'table', 'type': 'text'},
            'key': {'name': 'key', 'type': 'text'},
            'value': {'name': 'value', 'type': 'long_text'},
            'mode': {'name': 'mode', 'type': 'number', 'number_decimal_places': 0}
        }
        
        for field_name, config in field_configs.items():
            if field_name not in existing_fields:
                requests.post(
                    f"{base_url}/api/database/fields/table/{table_id}/",
                    json=config,
                    headers=headers,
                    timeout=10
                )
                log_info(f"Created '{field_name}' field")
                
    except Exception as e:
        log_warning(f"Field setup error: {e}")


def _baserow_create_token(base_url: str, headers: Dict[str, str], workspace_id: int) -> Optional[str]:
    """Create database API token."""
    try:
        # Delete existing token if present
        tokens_response = requests.get(
            f"{base_url}/api/database/tokens/",
            headers=headers,
            timeout=10
        )
        
        if tokens_response.ok:
            tokens = tokens_response.json()
            existing_token = next(
                (t for t in tokens if t.get('name') == 'dictature_test_token'),
                None
            )
            if existing_token:
                requests.delete(
                    f"{base_url}/api/database/tokens/{existing_token['id']}/",
                    headers=headers
                )
                log_info("Deleted existing token")
        
        # Create new token
        create_response = requests.post(
            f"{base_url}/api/database/tokens/",
            json={"name": "dictature_test_token", "workspace": workspace_id},
            headers=headers,
            timeout=10
        )
        
        if not create_response.ok:
            log_warning(f"Could not create token: {create_response.status_code}")
            return None
        
        token_data = create_response.json()
        api_key = token_data.get('key')
        token_id = token_data.get('id')
        
        log_info(f"Created Database Token: {api_key[:8]}...")
        
        # Set permissions
        requests.patch(
            f"{base_url}/api/database/tokens/{token_id}/",
            json={"permissions": {"create": True, "read": True, "update": True, "delete": True}},
            headers=headers,
            timeout=10
        )
        log_info("Set full permissions for Database Token")
        
        return api_key
        
    except Exception as e:
        log_warning(f"Token creation error: {e}")
        return None


def parse_arguments() -> argparse.Namespace:
    """
    Parse command line arguments.
    
    Returns:
        Parsed arguments with backend enable/disable flags
    """
    parser = argparse.ArgumentParser(
        description='Run tests with backend services (MySQL, S3, WebDAV, MISP, Baserow)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s                    # Run all tests
  %(prog)s --no-baserow       # Skip Baserow tests
  %(prog)s --no-misp --no-baserow  # Skip MISP and Baserow tests
  %(prog)s --only-mysql --only-s3  # Run only MySQL and S3 tests
  %(prog)s --only-misp --no-mysql  # Run only MISP (--no-mysql ignored since MySQL is needed by MISP)
        '''
    )
    
    parser.add_argument('--only-mysql', action='store_true',
                        help='Run only MySQL backend tests')
    parser.add_argument('--only-s3', action='store_true',
                        help='Run only S3 backend tests')
    parser.add_argument('--only-webdav', action='store_true',
                        help='Run only WebDAV backend tests')
    parser.add_argument('--only-misp', action='store_true',
                        help='Run only MISP backend tests')
    parser.add_argument('--only-baserow', action='store_true',
                        help='Run only Baserow backend tests')
    
    parser.add_argument('--no-mysql', action='store_true',
                        help='Skip MySQL backend tests')
    parser.add_argument('--no-s3', action='store_true',
                        help='Skip S3 backend tests')
    parser.add_argument('--no-webdav', action='store_true',
                        help='Skip WebDAV backend tests')
    parser.add_argument('--no-misp', action='store_true',
                        help='Skip MISP backend tests')
    parser.add_argument('--no-baserow', action='store_true',
                        help='Skip Baserow backend tests')
    
    return parser.parse_args()


def main() -> None:
    """Main entry point for test runner."""
    args = parse_arguments()
    
    # Determine enabled backends
    # Step 1: Check if any --only-* flags are set
    only_flags = {
        'mysql': args.only_mysql,
        's3': args.only_s3,
        'webdav': args.only_webdav,
        'misp': args.only_misp,
        'baserow': args.only_baserow,
    }
    
    any_only = any(only_flags.values())
    
    # Step 2: Start with all enabled, or only the --only-* ones if any are specified
    if any_only:
        enabled_backends = only_flags.copy()
    else:
        enabled_backends = {backend: True for backend in only_flags.keys()}
    
    # Step 3: Apply --no-* flags
    if args.no_mysql:
        enabled_backends['mysql'] = False
    if args.no_s3:
        enabled_backends['s3'] = False
    if args.no_webdav:
        enabled_backends['webdav'] = False
    if args.no_misp:
        enabled_backends['misp'] = False
    if args.no_baserow:
        enabled_backends['baserow'] = False
    
    # Log backend status
    enabled_list = [name for name, enabled in enabled_backends.items() if enabled]
    disabled_list = [name for name, enabled in enabled_backends.items() if not enabled]
    
    if enabled_list:
        log_info(f"Enabled backends: {', '.join(enabled_list)}")
    if disabled_list:
        log_warning(f"Disabled backends: {', '.join(disabled_list)}")
    
    docker_compose_file = 'dictature-test-backends-compose.yml'
    
    def cleanup(signum=None, frame=None) -> None:
        """Cleanup handler for graceful shutdown."""
        log_info("Cleaning up...")
        stop_services(docker_compose_file)
        sys.exit(0)
    
    # Register signal handlers for cleanup
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    
    try:
        # Start and configure services
        start_services(docker_compose_file, enabled_backends)
        wait_for_services(enabled_backends)
        setup_environment_variables(enabled_backends)
        
        if enabled_backends['s3']:
            create_s3_bucket()
        
        # Setup MISP authentication
        if enabled_backends['misp']:
            misp_key = misp_register_and_get_key()
            if misp_key:
                os.environ['MISP_KEY'] = misp_key
                log_info("Set MISP_KEY environment variable")
        
        # Setup Baserow authentication
        if enabled_backends['baserow']:
            result = baserow_register_and_get_token()
            if result:
                api_key, table_id = result
                os.environ['BASEROW_TOKEN'] = api_key
                os.environ['BASEROW_TABLE_ID'] = str(table_id)
                log_info("Set BASEROW_TOKEN, BASEROW_TABLE_ID, and BASEROW_URL environment variables")
        
        # Run tests
        success = run_tests()
        
        if success:
            log_info("All tests passed successfully")
        else:
            log_error("Some tests failed")
        
        sys.exit(0 if success else 1)
    
    except Exception as e:
        log_error(f"Fatal error: {e}")
        stop_services(docker_compose_file)
        sys.exit(1)


if __name__ == '__main__':
    main()
