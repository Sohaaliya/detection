import scapy.all as scapy
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
import random

print("🔥 NIDS LOADED - Real packet capture ready!")

class NIDS:
    def __init__(self):
        self.lock = threading.Lock()
        self.reset_counters()
        self.running = False
        self.alerts = deque(maxlen=50)
        self.total_attacks = self.port_scans = self.icmp_attacks = self.brute_force = 0
        self.ip_stats = defaultdict(lambda: {'packets': 0, 'attacks': 0})

    def reset_counters(self):
        with self.lock:
            self.icmp_counts = defaultdict(int)
            self.port_attempts = defaultdict(set)
            self.conn_attempts = defaultdict(int)
            self.packet_counts = defaultdict(int)

    def packet_handler(self, packet):
        try:
            print(f"📦 Packet: {packet.summary()}")

            if scapy.IP not in packet:
                return

            ip = packet[scapy.IP].src
            with self.lock:
                self.packet_counts[ip] += 1
                self.ip_stats[ip]['packets'] += 1

                # 🚨 ICMP FLOOD
                if scapy.ICMP in packet and packet[scapy.ICMP].type == 8:
                    self.icmp_counts[ip] += 1
                    if self.icmp_counts[ip] >= 5:
                        self._generate_alert("🚨 ICMP FLOOD", ip)
                        self.icmp_attacks += 1
                        self.icmp_counts[ip] = 0

                # 🔍 PORT SCAN (multiple ports)
                if scapy.TCP in packet and packet[scapy.TCP].flags & 0x02:
                    port = packet[scapy.TCP].dport
                    self.port_attempts[ip].add(port)
                    if len(self.port_attempts[ip]) >= 3:
                        self._generate_alert("🔍 PORT SCAN", ip)
                        self.port_scans += 1
                        self.port_attempts[ip].clear()

                # 💥 BRUTE FORCE (same IP + same port repeatedly)
                if scapy.TCP in packet and packet[scapy.TCP].flags & 0x02:
                    key = (ip, packet[scapy.TCP].dport)
                    self.conn_attempts[key] += 1
                    if self.conn_attempts[key] >= 10:
                        self._generate_alert("💥 BRUTE FORCE", ip)
                        self.brute_force += 1
                        self.conn_attempts[key] = 0

        except Exception as e:
            print("Error:", e)

    def _generate_alert(self, attack_type, ip):
        alert = {
            "attack": attack_type,
            "ip": ip,
            "confidence": 0.98,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self.alerts.append(alert)
        self.total_attacks += 1
        self.ip_stats[ip]['attacks'] += 1
        print(f"🚨 ALERT: {attack_type} from {ip}")

    def start_monitoring(self):
        if self.running:
            return
        self.reset_counters()
        self.running = True

        def sniff_loop():
            print("🔍 SNIFFER STARTED - Capturing live traffic...")
            while self.running:
                scapy.sniff(
                    prn=self.packet_handler,
                    filter="icmp or tcp",
                    store=0,
                    timeout=1
                )

        threading.Thread(target=sniff_loop, daemon=True).start()

    def stop_monitoring(self):
        self.running = False

    def get_stats(self):
        top_ips = sorted(self.ip_stats.items(), key=lambda x: x[1]['attacks'], reverse=True)[:5]
        return {
            "total_attacks": self.total_attacks,
            "port_scans": self.port_scans,
            "icmp_attacks": self.icmp_attacks,
            "brute_force": self.brute_force,
            "running": self.running,
            "alerts": list(self.alerts),
            "top_attackers": [
                {"ip": ip, "attacks": stats['attacks'], "packets": stats['packets']}
                for ip, stats in top_ips
            ],
            "attack_rate": 0
        }

    def simulate_attack(self):
        print("💥 SIMULATE ATTACK")
        attacks = ["🧪 ICMP FLOOD", "🔍 PORT SCAN", "💥 BRUTE FORCE"]
        ip = f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
        self._generate_alert(random.choice(attacks), ip)

# 🔥 Global instance
nids = NIDS()
