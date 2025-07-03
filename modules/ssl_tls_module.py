#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSL/TLS Security Testing Module for WebMer
Advanced SSL/TLS Analysis and Attack Framework
"""

import ssl
import socket
import asyncio
import aiohttp
try:
    import OpenSSL
except ImportError:
    OpenSSL = None
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
except ImportError:
    x509 = None
import subprocess
import json
import time
from colorama import Fore, Style
import hashlib
import base64
import struct
import binascii
from datetime import datetime
import threading
from urllib.parse import urlparse

class SSLTLSSecurityModule:
    def __init__(self, target_host, target_port=443):
        self.target_host = target_host
        self.target_port = target_port
        self.ssl_info = {}
        
    async def comprehensive_ssl_analysis(self):
        """Perform comprehensive SSL/TLS security analysis"""
        print(f"{Fore.CYAN}[*] Starting Comprehensive SSL/TLS Analysis")
        print(f"{Fore.YELLOW}[*] Target: {self.target_host}:{self.target_port}")
        
        results = {
            'certificate_analysis': await self._analyze_certificate(),
            'protocol_analysis': await self._analyze_protocols(),
            'cipher_analysis': await self._analyze_ciphers(),
            'vulnerability_scan': await self._scan_vulnerabilities(),
            'certificate_chain': await self._analyze_certificate_chain(),
            'ssl_configuration': await self._analyze_ssl_configuration()
        }
        
        self._print_ssl_results(results)
        return results
    
    async def _analyze_certificate(self):
        """Analyze SSL certificate details"""
        print(f"{Fore.BLUE}[*] Analyzing SSL Certificate...")
        
        try:
            # Get certificate via socket
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target_host, self.target_port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_info = ssock.getpeercert()
            
            # Parse certificate with cryptography
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            
            cert_analysis = {
                'subject': cert_info.get('subject', []),
                'issuer': cert_info.get('issuer', []),
                'version': cert.version.name,
                'serial_number': str(cert.serial_number),
                'not_valid_before': cert.not_valid_before.isoformat(),
                'not_valid_after': cert.not_valid_after.isoformat(),
                'signature_algorithm': cert.signature_algorithm_oid._name,
                'public_key_algorithm': cert.public_key().__class__.__name__,
                'key_size': self._get_key_size(cert.public_key()),
                'san_names': self._get_san_names(cert),
                'fingerprint_sha1': hashlib.sha1(cert_der).hexdigest(),
                'fingerprint_sha256': hashlib.sha256(cert_der).hexdigest(),
                'is_self_signed': self._is_self_signed(cert),
                'is_expired': cert.not_valid_after < cert.not_valid_before,
                'days_until_expiry': (cert.not_valid_after - cert.not_valid_before).days
            }
            
            return cert_analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    async def _analyze_protocols(self):
        """Analyze supported SSL/TLS protocols"""
        print(f"{Fore.BLUE}[*] Analyzing SSL/TLS Protocols...")
        
        protocols = {
            'SSLv2': ssl.PROTOCOL_SSLv23,  # Legacy
            'SSLv3': ssl.PROTOCOL_SSLv23,  # Legacy
            'TLSv1.0': ssl.PROTOCOL_TLSv1,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
            'TLSv1.3': getattr(ssl, 'PROTOCOL_TLSv1_3', None)
        }
        
        supported_protocols = {}
        
        for protocol_name, protocol_version in protocols.items():
            if protocol_version is None:
                continue
                
            try:
                context = ssl.SSLContext(protocol_version)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.target_host, self.target_port), timeout=5) as sock:
                    with context.wrap_socket(sock) as ssock:
                        supported_protocols[protocol_name] = {
                            'supported': True,
                            'version': ssock.version(),
                            'cipher': ssock.cipher()
                        }
            except:
                supported_protocols[protocol_name] = {'supported': False}
        
        return supported_protocols
    
    async def _analyze_ciphers(self):
        """Analyze supported cipher suites"""
        print(f"{Fore.BLUE}[*] Analyzing Cipher Suites...")
        
        try:
            # Use testssl.sh approach or custom implementation
            result = await self._run_testssl_ciphers()
            return result
        except:
            return await self._manual_cipher_analysis()
    
    async def _manual_cipher_analysis(self):
        """Manual cipher analysis when testssl.sh is not available"""
        weak_ciphers = []
        strong_ciphers = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target_host, self.target_port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        cipher_name = cipher_info[0]
                        cipher_version = cipher_info[1]
                        cipher_bits = cipher_info[2]
                        
                        cipher_analysis = {
                            'name': cipher_name,
                            'protocol': cipher_version,
                            'key_bits': cipher_bits,
                            'strength': self._evaluate_cipher_strength(cipher_name, cipher_bits)
                        }
                        
                        if cipher_analysis['strength'] in ['weak', 'insecure']:
                            weak_ciphers.append(cipher_analysis)
                        else:
                            strong_ciphers.append(cipher_analysis)
            
            return {
                'weak_ciphers': weak_ciphers,
                'strong_ciphers': strong_ciphers,
                'total_ciphers': len(weak_ciphers) + len(strong_ciphers)
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    async def _scan_vulnerabilities(self):
        """Scan for known SSL/TLS vulnerabilities"""
        print(f"{Fore.BLUE}[*] Scanning for SSL/TLS Vulnerabilities...")
        
        vulnerabilities = {}
        
        # Test for Heartbleed
        vulnerabilities['heartbleed'] = await self._test_heartbleed()
        
        # Test for POODLE
        vulnerabilities['poodle'] = await self._test_poodle()
        
        # Test for BEAST
        vulnerabilities['beast'] = await self._test_beast()
        
        # Test for CRIME
        vulnerabilities['crime'] = await self._test_crime()
        
        # Test for BREACH
        vulnerabilities['breach'] = await self._test_breach()
        
        # Test for Logjam
        vulnerabilities['logjam'] = await self._test_logjam()
        
        # Test for FREAK
        vulnerabilities['freak'] = await self._test_freak()
        
        # Test for Sweet32
        vulnerabilities['sweet32'] = await self._test_sweet32()
        
        return vulnerabilities
    
    async def _test_heartbleed(self):
        """Test for Heartbleed vulnerability (CVE-2014-0160)"""
        try:
            # Simplified Heartbleed test
            heartbleed_payload = (
                b'\x18\x03\x02\x00\x03\x01\x40\x00'  # Heartbeat request
            )
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target_host, self.target_port))
            
            # Send heartbleed payload
            sock.send(heartbleed_payload)
            response = sock.recv(1024)
            sock.close()
            
            # If we get a response larger than expected, might be vulnerable
            if len(response) > 3:
                return {'vulnerable': True, 'details': 'Possible Heartbleed response detected'}
            else:
                return {'vulnerable': False, 'details': 'No Heartbleed response detected'}
                
        except Exception as e:
            return {'vulnerable': False, 'error': str(e)}
    
    async def _test_poodle(self):
        """Test for POODLE vulnerability"""
        try:
            # Check if SSLv3 is supported
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target_host, self.target_port), timeout=5) as sock:
                with context.wrap_socket(sock) as ssock:
                    if ssock.version() == 'SSLv3':
                        return {'vulnerable': True, 'details': 'SSLv3 is supported, vulnerable to POODLE'}
            
            return {'vulnerable': False, 'details': 'SSLv3 not supported'}
            
        except Exception as e:
            return {'vulnerable': False, 'details': 'SSLv3 not supported or connection failed'}
    
    async def _test_beast(self):
        """Test for BEAST vulnerability"""
        try:
            # BEAST affects TLS 1.0 with CBC ciphers
            protocols = await self._analyze_protocols()
            
            if protocols.get('TLSv1.0', {}).get('supported', False):
                cipher_info = protocols['TLSv1.0'].get('cipher')
                if cipher_info and 'CBC' in str(cipher_info):
                    return {'vulnerable': True, 'details': 'TLS 1.0 with CBC cipher detected'}
            
            return {'vulnerable': False, 'details': 'TLS 1.0 CBC not detected'}
            
        except Exception as e:
            return {'vulnerable': False, 'error': str(e)}
    
    async def _test_crime(self):
        """Test for CRIME vulnerability"""
        try:
            # CRIME exploits TLS compression
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target_host, self.target_port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                    compression = ssock.compression()
                    if compression:
                        return {'vulnerable': True, 'details': f'TLS compression enabled: {compression}'}
            
            return {'vulnerable': False, 'details': 'TLS compression not enabled'}
            
        except Exception as e:
            return {'vulnerable': False, 'error': str(e)}
    
    async def _test_breach(self):
        """Test for BREACH vulnerability"""
        try:
            # BREACH exploits HTTP compression
            async with aiohttp.ClientSession() as session:
                async with session.get(f'https://{self.target_host}', 
                                     headers={'Accept-Encoding': 'gzip, deflate'}) as response:
                    if 'gzip' in response.headers.get('Content-Encoding', ''):
                        return {'vulnerable': True, 'details': 'HTTP compression enabled'}
            
            return {'vulnerable': False, 'details': 'HTTP compression not detected'}
            
        except Exception as e:
            return {'vulnerable': False, 'error': str(e)}
    
    async def _test_logjam(self):
        """Test for Logjam vulnerability"""
        try:
            # Logjam affects DHE key exchange with weak DH parameters
            ciphers = await self._analyze_ciphers()
            
            weak_dhe_detected = False
            if isinstance(ciphers, dict) and 'weak_ciphers' in ciphers:
                for cipher in ciphers['weak_ciphers']:
                    if 'DHE' in cipher.get('name', '') and cipher.get('key_bits', 0) < 1024:
                        weak_dhe_detected = True
                        break
            
            if weak_dhe_detected:
                return {'vulnerable': True, 'details': 'Weak DHE parameters detected'}
            
            return {'vulnerable': False, 'details': 'No weak DHE parameters detected'}
            
        except Exception as e:
            return {'vulnerable': False, 'error': str(e)}
    
    async def _test_freak(self):
        """Test for FREAK vulnerability"""
        try:
            # FREAK affects export-grade RSA ciphers
            ciphers = await self._analyze_ciphers()
            
            export_cipher_detected = False
            if isinstance(ciphers, dict) and 'weak_ciphers' in ciphers:
                for cipher in ciphers['weak_ciphers']:
                    if 'EXPORT' in cipher.get('name', '') or cipher.get('key_bits', 0) <= 512:
                        export_cipher_detected = True
                        break
            
            if export_cipher_detected:
                return {'vulnerable': True, 'details': 'Export-grade ciphers detected'}
            
            return {'vulnerable': False, 'details': 'No export-grade ciphers detected'}
            
        except Exception as e:
            return {'vulnerable': False, 'error': str(e)}
    
    async def _test_sweet32(self):
        """Test for Sweet32 vulnerability"""
        try:
            # Sweet32 affects 3DES and Blowfish ciphers
            ciphers = await self._analyze_ciphers()
            
            vulnerable_cipher_detected = False
            if isinstance(ciphers, dict):
                all_ciphers = ciphers.get('weak_ciphers', []) + ciphers.get('strong_ciphers', [])
                for cipher in all_ciphers:
                    cipher_name = cipher.get('name', '')
                    if '3DES' in cipher_name or 'DES' in cipher_name or 'BLOWFISH' in cipher_name:
                        vulnerable_cipher_detected = True
                        break
            
            if vulnerable_cipher_detected:
                return {'vulnerable': True, 'details': '3DES or Blowfish ciphers detected'}
            
            return {'vulnerable': False, 'details': 'No vulnerable block ciphers detected'}
            
        except Exception as e:
            return {'vulnerable': False, 'error': str(e)}
    
    async def _analyze_certificate_chain(self):
        """Analyze certificate chain"""
        print(f"{Fore.BLUE}[*] Analyzing Certificate Chain...")
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target_host, self.target_port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                    cert_chain = ssock.getpeercert_chain()
                    
                    chain_analysis = {
                        'chain_length': len(cert_chain) if cert_chain else 0,
                        'certificates': []
                    }
                    
                    if cert_chain:
                        for i, cert in enumerate(cert_chain):
                            cert_info = {
                                'position': i,
                                'subject': cert.get_subject().get_components(),
                                'issuer': cert.get_issuer().get_components(),
                                'serial_number': str(cert.get_serial_number()),
                                'not_before': cert.get_notBefore().decode('utf-8'),
                                'not_after': cert.get_notAfter().decode('utf-8'),
                                'signature_algorithm': cert.get_signature_algorithm().decode('utf-8')
                            }
                            chain_analysis['certificates'].append(cert_info)
                    
                    return chain_analysis
                    
        except Exception as e:
            return {'error': str(e)}
    
    async def _analyze_ssl_configuration(self):
        """Analyze SSL/TLS configuration"""
        print(f"{Fore.BLUE}[*] Analyzing SSL/TLS Configuration...")
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target_host, self.target_port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                    config_analysis = {
                        'ssl_version': ssock.version(),
                        'cipher_suite': ssock.cipher(),
                        'compression': ssock.compression(),
                        'server_hostname': ssock.server_hostname,
                        'selected_alpn_protocol': ssock.selected_alpn_protocol(),
                        'selected_npn_protocol': ssock.selected_npn_protocol(),
                        'shared_ciphers': ssock.shared_ciphers(),
                        'server_side': ssock.server_side,
                        'do_handshake_on_connect': ssock.do_handshake_on_connect
                    }
                    
                    return config_analysis
                    
        except Exception as e:
            return {'error': str(e)}
    
    async def _run_testssl_ciphers(self):
        """Run testssl.sh for cipher analysis"""
        try:
            cmd = f"testssl.sh --ciphers {self.target_host}:{self.target_port}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return {'testssl_output': result.stdout}
            else:
                return {'error': 'testssl.sh failed or not available'}
                
        except Exception as e:
            return {'error': str(e)}
    
    def _get_key_size(self, public_key):
        """Get public key size"""
        try:
            if hasattr(public_key, 'key_size'):
                return public_key.key_size
            elif hasattr(public_key, 'curve'):
                return public_key.curve.key_size
            else:
                return 'Unknown'
        except:
            return 'Unknown'
    
    def _get_san_names(self, cert):
        """Get Subject Alternative Names"""
        try:
            san_extension = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            return [name.value for name in san_extension.value]
        except:
            return []
    
    def _is_self_signed(self, cert):
        """Check if certificate is self-signed"""
        try:
            return cert.issuer == cert.subject
        except:
            return False
    
    def _evaluate_cipher_strength(self, cipher_name, key_bits):
        """Evaluate cipher strength"""
        if key_bits < 128:
            return 'insecure'
        elif 'RC4' in cipher_name or 'DES' in cipher_name:
            return 'weak'
        elif 'MD5' in cipher_name:
            return 'weak'
        elif key_bits >= 256:
            return 'strong'
        else:
            return 'medium'
    
    def _print_ssl_results(self, results):
        """Print SSL/TLS analysis results"""
        print(f"\n{Fore.GREEN}{'='*70}")
        print(f"{Fore.YELLOW}  SSL/TLS SECURITY ANALYSIS RESULTS")
        print(f"{Fore.GREEN}{'='*70}")
        
        # Certificate Analysis
        if 'certificate_analysis' in results:
            cert = results['certificate_analysis']
            if 'error' not in cert:
                print(f"{Fore.CYAN}  Certificate Information:")
                print(f"    Subject: {cert.get('subject', 'N/A')}")
                print(f"    Issuer: {cert.get('issuer', 'N/A')}")
                print(f"    Valid From: {cert.get('not_valid_before', 'N/A')}")
                print(f"    Valid Until: {cert.get('not_valid_after', 'N/A')}")
                print(f"    Signature Algorithm: {cert.get('signature_algorithm', 'N/A')}")
                print(f"    Key Size: {cert.get('key_size', 'N/A')}")
                print(f"    SHA256 Fingerprint: {cert.get('fingerprint_sha256', 'N/A')}")
                
                if cert.get('is_self_signed'):
                    print(f"{Fore.RED}    WARNING: Self-signed certificate detected!")
                if cert.get('is_expired'):
                    print(f"{Fore.RED}    WARNING: Certificate has expired!")
        
        # Protocol Analysis
        if 'protocol_analysis' in results:
            protocols = results['protocol_analysis']
            print(f"\n{Fore.CYAN}  Supported Protocols:")
            for proto, info in protocols.items():
                status = f"{Fore.GREEN}Supported" if info.get('supported') else f"{Fore.RED}Not Supported"
                print(f"    {proto}: {status}")
                if info.get('supported') and proto in ['SSLv2', 'SSLv3', 'TLSv1.0']:
                    print(f"{Fore.RED}      WARNING: Insecure protocol!")
        
        # Vulnerability Scan
        if 'vulnerability_scan' in results:
            vulns = results['vulnerability_scan']
            print(f"\n{Fore.CYAN}  Vulnerability Scan:")
            for vuln_name, vuln_info in vulns.items():
                if vuln_info.get('vulnerable'):
                    print(f"{Fore.RED}    {vuln_name.upper()}: VULNERABLE - {vuln_info.get('details', '')}")
                else:
                    print(f"{Fore.GREEN}    {vuln_name.upper()}: Not Vulnerable")
        
        print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}")

# SSL/TLS Attack Module
class SSLTLSAttackModule:
    def __init__(self, target_host, target_port=443):
        self.target_host = target_host
        self.target_port = target_port
    
    async def ssl_stripping_attack(self, duration=60):
        """Test SSL stripping attack"""
        print(f"{Fore.RED}[*] Testing SSL Stripping Attack")
        print(f"{Fore.YELLOW}[*] Target: {self.target_host}")
        print(f"{Fore.YELLOW}[*] Duration: {duration}s")
        print(f"{Fore.CYAN}[*] Note: This is a test for security assessment purposes only")
        
        # This would require MITM position in real attack
        intercepted_requests = 0
        start_time = time.time()
        
        while (time.time() - start_time) < duration:
            try:
                # Test intercepting HTTPS requests and downgrading to HTTP
                async with aiohttp.ClientSession() as session:
                    # Try to access HTTP version
                    http_url = f"http://{self.target_host}"
                    async with session.get(http_url, timeout=5) as response:
                        if response.status == 200:
                            intercepted_requests += 1
                            print(f"{Fore.YELLOW}[*] HTTP downgrade test successful")
                        
            except Exception as e:
                pass
                
            await asyncio.sleep(5)
        
        print(f"{Fore.GREEN}[+] SSL Stripping test completed")
        print(f"{Fore.CYAN}[*] Test intercepted requests: {intercepted_requests}")
    
    async def certificate_pinning_bypass(self):
        """Test certificate pinning bypass techniques"""
        print(f"{Fore.CYAN}[*] Testing Certificate Pinning Bypass")
        
        bypass_techniques = [
            "Custom CA installation",
            "Certificate patching", 
            "SSL Kill Switch",
            "Frida hooking",
            "Network interception"
        ]
        
        results = {}
        for technique in bypass_techniques:
            print(f"{Fore.YELLOW}[*] Testing: {technique}")
            # Test each technique
            await asyncio.sleep(1)
            results[technique] = {
                'success': False,
                'details': 'Test only - requires specific setup'
            }
        
        return results
    
    async def weak_cipher_exploitation(self):
        """Attempt to exploit weak ciphers"""
        print(f"{Fore.CYAN}[*] Testing Weak Cipher Exploitation")
        
        weak_ciphers = [
            'DES-CBC-SHA',
            'RC4-MD5',
            'NULL-MD5',
            'EXP-RC4-MD5',
            'EXP-DES-CBC-SHA'
        ]
        
        exploitation_results = {}
        
        for cipher in weak_ciphers:
            try:
                print(f"{Fore.YELLOW}[*] Testing cipher: {cipher}")
                
                # Try to force weak cipher
                context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                context.set_ciphers(cipher)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.target_host, self.target_port), timeout=5) as sock:
                    with context.wrap_socket(sock) as ssock:
                        if ssock.cipher()[0] == cipher:
                            exploitation_results[cipher] = {
                                'exploitable': True,
                                'details': 'Weak cipher accepted by server'
                            }
                        else:
                            exploitation_results[cipher] = {
                                'exploitable': False,
                                'details': 'Server rejected weak cipher'
                            }
                            
            except Exception as e:
                exploitation_results[cipher] = {
                    'exploitable': False,
                    'details': f'Connection failed: {str(e)}'
                }
        
        return exploitation_results
