import scapy.all as scapy
from collections import defaultdict, deque
from datetime import datetime, timedelta
import threading
import time
import json
from typing import Dict, List
import pandas as pd
import random
import platform

class NIDS:
    def __init__(self):
        self.port_attempts = defaultdict(set)
        self.icmp_counts = defaultdict(int)
        self.conn_attempts = defaultdict(int)
        self.timestamps = defaultdict(list)
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.total_attacks = 0
        self.port_scans = 0
        self.icmp_attacks = 0
        self.brute_force = 0
        self.suspicious_traffic = 0
        self.alerts: List[Dict] = []
        self.running = False
        
        # Analytics Data
        self.attack_history = deque(maxlen=1000)
        self.ip_stats = defaultdict(lambda: {'packets': 0, 'attacks': 0})
        self.hourly_attacks = defaultdict(int)

    def packet_handler(self, packet):
        """Real packet handler (for Linux/Mac with Npcap)"""
        if scapy.IP not in packet:
            return
            
        ip_src = packet[scapy.IP].src
        now = time.time()
        current_hour = datetime.now().hour
        
        with self.lock:
            self.timestamps[ip_src] = [t for t in self.timestamps[ip_src] if now - t < 60]
            self.timestamps[ip_src].append(now)
            self.ip_stats[ip_src]['packets'] += 1
            
            if scapy.TCP in packet:
                port = packet[scapy.TCP].dport
                self.port_attempts[ip_src].add(port)
                if len(self.port_attempts[ip_src]) > 10:
                    self._generate_alert("Port Scan", ip_src)
                
                self.conn_attempts[ip_src] += 1
                if self.conn_attempts[ip_src] > 20:
                    self._generate_alert("Brute Force", ip_src)
            
            if scapy.ICMP in packet:
                self.icmp_counts[ip_src] += 1
                if self.icmp_counts[ip_src] > 50:
                    self._generate_alert("ICMP Flood", ip_src)
            
            if len(self.timestamps[ip_src]) > 100:
                self._generate_alert("Suspicious Traffic", ip_src)
            
            self.hourly_attacks[current_hour] += 1
            self.attack_history.append({
                'timestamp': datetime.now(),
                'src_ip': ip_src,
                'protocol': packet.proto if hasattr(packet, 'proto') else 'unknown'
            })

    def _generate_alert(self, attack_type: str, ip: str):
        """Generate and store alert"""
        alert = {
            "attack": attack_type,
            "ip": ip,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self.alerts.append(alert)
        self.total_attacks += 1
        
        if "Port" in attack_type:
            self.port_scans += 1
        elif "ICMP" in attack_type:
            self.icmp_attacks += 1
        elif "Brute" in attack_type:
            self.brute_force += 1
        else:
            self.suspicious_traffic += 1
        
        self.ip_stats[ip]['attacks'] += 1
        
        if len(self.alerts) > 100:
            self.alerts = self.alerts[-100:]
        
        print(f"[🚨 ALERT] {attack_type} from {ip}")

    def _sniff_packets(self, interface):
        """Real packet sniffing (Linux/Mac)"""
        scapy.sniff(iface=interface, prn=self.packet_handler, 
                   store=0, stop_filter=lambda _: self.stop_event.is_set())

    def _windows_demo(self):
        """🔥 HYPER-REALISTIC Windows simulation"""
        print("🪟 WINDOWS MODE: Hyper-realistic attack simulation ACTIVE")
        print("📡 All graphs, analytics, chatbot work 100%!")
        
        attack_types = [
            "Port Scan", "ICMP Flood", "Brute Force", "Suspicious Traffic", 
            "SYN Flood", "DNS Amplification", "Port Scan", "Brute Force"
        ]
        ip_prefixes = ["192.168.1.", "10.0.0.", "172.16.", "203.0.113.", "198.51.100."]
        
        attack_patterns = {
            "Port Scan": lambda: f"{random.choice(ip_prefixes)}{random.randint(10, 255)}",
            "ICMP Flood": lambda: f"10.0.{random.randint(10, 99)}.{random.randint(1, 255)}",
            "Brute Force": lambda: f"192.168.{random.randint(1, 255)}.10",
        }
        
        burst_counter = 0
        while self.running:
            # Realistic timing: bursts + quiet periods
            if burst_counter > 0:
                time.sleep(random.uniform(1, 3))  # Burst mode
                burst_counter -= 1
            else:
                time.sleep(random.uniform(5, 20))  # Quiet period
                if random.random() < 0.7:  # 70% chance of burst
                    burst_counter = random.randint(2, 5)
            
            # Generate realistic IP and attack
            attack = random.choice(attack_types)
            ip = attack_patterns.get(attack, lambda: f"{random.choice(ip_prefixes)}{random.randint(10, 255)}")()
            
            # High severity attacks occasionally
            if random.random() < 0.25:
                attack = f"🚨 HIGH SEVERITY {attack}"
            
            self._generate_alert(attack, ip)
            
            # Update hourly stats
            current_hour = datetime.now().hour
            self.hourly_attacks[current_hour] += 1

    def is_windows(self):
        """Detect Windows OS"""
        return platform.system() == "Windows"

    def start_monitoring(self, interface: str = None):
        """🚀 Smart cross-platform monitoring"""
        if self.running:
            print("⚠️ NIDS already running!")
            return
        
        self.running = True
        print("🔥 NIDS Monitoring Started!")
        
        if self.is_windows():
            print("🪟 Windows: Using hyper-realistic simulation mode")
            print("📊 Perfect for demos, portfolios, testing!")
            threading.Thread(target=self._windows_demo, daemon=True).start()
        else:
            try:
                interface = interface or scapy.conf.iface
                print(f"🌐 Real packet capture on {interface}")
                threading.Thread(target=self._sniff_packets, args=(interface,), daemon=True).start()
            except Exception as e:
                print(f"⚠️ Real capture failed: {e}")
                print("🔄 Falling back to simulation mode...")
                threading.Thread(target=self._windows_demo, daemon=True).start()

    def stop_monitoring(self):
        """Stop monitoring"""
        self.stop_event.set()
        self.running = False
        print("⏹️ NIDS Monitoring Stopped")

    def get_stats(self):
        """Get comprehensive statistics"""
        with self.lock:
            top_ips = sorted(self.ip_stats.items(), 
                           key=lambda x: x[1]['attacks'], reverse=True)[:5]
            
            analytics = {
                "total_attacks": self.total_attacks,
                "port_scans": self.port_scans,
                "icmp_attacks": self.icmp_attacks,
                "brute_force": self.brute_force,
                "suspicious_traffic": self.suspicious_traffic,
                "alerts": self.alerts[-10:],
                "running": self.running,
                "top_attackers": [{"ip": ip, "attacks": stats['attacks']} 
                                for ip, stats in top_ips],
                "attack_rate": len(self.alerts[-60:]) if self.alerts else 0,
                "unique_ips": len(self.ip_stats),
                "hourly_attacks": dict(self.hourly_attacks),
                "is_windows": self.is_windows()
            }
            return analytics

    def simulate_attack(self):
        """Manual attack simulation for demos"""
        attack_types = ["Port Scan", "ICMP Flood", "Brute Force"]
        ip = f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
        attack = random.choice(attack_types)
        self._generate_alert(attack, ip)
        print(f"💥 Simulated {attack} from {ip}")

    def get_analytics_data(self):
        """Detailed analytics for charts"""
        df_alerts = pd.DataFrame(self.alerts[-100:])
        if not df_alerts.empty:
            df_alerts['time'] = pd.to_datetime(df_alerts['time'])
            return {
                "alerts_df": df_alerts,
                "attack_history": list(self.attack_history)[-200:]
            }
        return {"alerts_df": pd.DataFrame(), "attack_history": []}

# Test the NIDS
if __name__ == "__main__":
    nids = NIDS()
    nids.start_monitoring()
    try:
        while True:
            time.sleep(1)
            print(f"Stats: {nids.get_stats()['total_attacks']} attacks")
    except KeyboardInterrupt:
        nids.stop_monitoring()
