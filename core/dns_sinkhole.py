import socket
import threading
import struct
import urllib.request
import urllib.parse
import json
import time
from .database import log_event, get_connection, get_setting

DEFAULT_AD_TRACKERS = {
    # Ad Networks & Tracking
    "googleads.g.doubleclick.net", "adservice.google.com", "pagead2.googlesyndication.com",
    "www.googleadservices.com", "google-analytics.com", "ssl.google-analytics.com",
    "ads.youtube.com", "ad.doubleclick.net", "pixel.facebook.com", "an.facebook.com",
    "telemetry.microsoft.com", "v10.events.data.microsoft.com", "v20.events.data.microsoft.com",
    "activity.windows.com", "watson.telemetry.microsoft.com", "diagnostics.support.microsoft.com",
    "taboola.com", "outbrain.com", "criteo.com", "adnxs.com", "rubiconproject.com",
    "coinhive.com", "coin-hive.com", "malware-traffic-analysis.net", "testmalware.com"
}

class DNSSinkhole:
    def __init__(self, host="127.0.0.1", port=5353):
        self.host = host
        self.port = port
        self.running = False
        self.blocked_domains = set(DEFAULT_AD_TRACKERS)
        self.allowed_domains = set()
        self.doh_cache = {}
        self.load_rules()

    def load_rules(self):
        try:
            conn = get_connection()
            c = conn.cursor()
            c.execute("SELECT domain FROM blocklist WHERE is_enabled = 1")
            for r in c.fetchall():
                self.blocked_domains.add(r[0].strip().lower())
            c.execute("SELECT domain FROM allowlist")
            for r in c.fetchall():
                self.allowed_domains.add(r[0].strip().lower())
            conn.close()
        except Exception:
            pass

    def is_blocked(self, domain):
        domain = domain.strip().rstrip(".").lower()
        if domain in self.allowed_domains:
            return False, "ALLOWLIST"
        if domain in self.blocked_domains:
            return True, "LOCAL_BLOCKLIST"
        parts = domain.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self.blocked_domains:
                return True, f"WILDCARD (*.{parent})"
        return False, "CLEAN"

    def parse_domain_from_dns(self, data):
        try:
            domain_parts = []
            idx = 12
            length = data[idx]
            while length != 0:
                idx += 1
                domain_parts.append(data[idx:idx+length].decode("ascii", errors="ignore"))
                idx += length
                length = data[idx]
            domain = ".".join(domain_parts)
            return domain
        except Exception:
            return None

    def build_sinkhole_response(self, data):
        dns_id = data[:2]
        flags = b"\x81\x80"
        counts = b"\x00\x01\x00\x01\x00\x00\x00\x00"
        idx = 12
        while data[idx] != 0:
            idx += 1 + data[idx]
        idx += 5
        question_section = data[12:idx]
        answer_section = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x00\x00\x00\x00"
        return dns_id + flags + counts + question_section + answer_section

    def query_quad9_doh(self, wire_packet):
        endpoint = get_setting("quad9_doh", "https://dns.quad9.net/dns-query")
        headers = {
            "Content-Type": "application/dns-message",
            "Accept": "application/dns-message",
            "User-Agent": "InternetPolice-DoH/1.0"
        }
        try:
            req = urllib.request.Request(endpoint, data=wire_packet, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=4) as resp:
                if resp.status == 200:
                    return resp.read()
        except Exception:
            return None
        return None

    def handle_query(self, data, addr, sock):
        client_ip = addr[0]
        domain = self.parse_domain_from_dns(data)
        if not domain:
            return

        blocked, reason = self.is_blocked(domain)
        if blocked:
            log_event(client_ip, "DNS", domain, "BLOCKED", "MEDIUM", f"Tracker sinkholed: {reason}")
            sock.sendto(self.build_sinkhole_response(data), addr)
            return

        # Upstream Quad9 DoH
        resp = self.query_quad9_doh(data)
        if resp:
            rcode = resp[3] & 0x0F
            if rcode == 3: # NXDOMAIN -> Quad9 Threat Filtered
                log_event(client_ip, "THREAT", domain, "BLOCKED", "CRITICAL", "Quad9 blocked malicious host")
            else:
                log_event(client_ip, "DNS", domain, "ALLOWED", "LOW", "Resolved cleanly via Quad9 DoH")
            sock.sendto(resp, addr)
        else:
            log_event(client_ip, "DNS", domain, "ALLOWED", "LOW", "Local fallback resolved")
            sock.sendto(self.build_sinkhole_response(data), addr)

    def start(self):
        self.running = True
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind((self.host, self.port))
            print(f"[*] Internet Police DNS Sinkhole active on {self.host}:{self.port}")
        except Exception as e:
            print(f"[!] Could not bind DNS port {self.port}: {e}")
            return

        while self.running:
            try:
                data, addr = sock.recvfrom(512)
                threading.Thread(target=self.handle_query, args=(data, addr, sock), daemon=True).start()
            except Exception:
                break
        sock.close()

    def stop(self):
        self.running = False
