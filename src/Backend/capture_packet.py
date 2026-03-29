
''' Prologue Comments 
Artifact: capture_packet.py
Description: Sniffs local traffic and obtains Scapy packet object.
Programmer's name: Mohamed Ashraq
Creation Date: 2/12/2026
Revision Dates:
    2/15/2026: Revised to allow packet capture on different OS systems' network interface.
    2026-03-25: Improved interface auto-detection so the sniffer actually finds active traffic.
Preconditions:
    Must be run with sudo / admin privileges for raw packet capture.
Postconditions:
    Puts captured packets onto the `packets` Queue for Metadata_extraction.py to consume.
Errors/Exceptions:
    Raises if no suitable network interface found.
Side effects: none
Invariants: none
'''

from scapy.all import sniff, get_if_list, conf
from queue import Queue
import os
import threading
import subprocess

def _detect_interface():
    """
    Pick the best interface for live capture.
    Priority order:
      1. NETGUARD_IFACE env var (lets user override without editing code)
      2. macOS: first 'en' interface that is UP and has an IPv4 address
      3. Linux: first non-loopback interface that is UP
      4. Fallback: scapy's default conf.iface
    """
    # Allow explicit override via environment variable
    env_iface = os.environ.get("NETGUARD_IFACE")
    if env_iface:
        print(f"[CAPTURE] Using interface from NETGUARD_IFACE env var: {env_iface}")
        return env_iface

    import platform
    system = platform.system()

    try:
        from scapy.all import get_if_addr
        all_ifaces = get_if_list()

        if system == "Darwin":  # macOS
            # Prefer en0, en1, ... that have a real IP
            for candidate in ["en0", "en1", "en2", "en3"]:
                if candidate in all_ifaces:
                    try:
                        ip = get_if_addr(candidate)
                        if ip and ip != "0.0.0.0":
                            print(f"[CAPTURE] macOS: selected interface {candidate} ({ip})")
                            return candidate
                    except Exception:
                        pass
            # Fallback: any en* with an IP
            for iface in all_ifaces:
                if iface.startswith("en"):
                    try:
                        ip = get_if_addr(iface)
                        if ip and ip != "0.0.0.0":
                            print(f"[CAPTURE] macOS fallback: {iface} ({ip})")
                            return iface
                    except Exception:
                        pass

        else:  # Linux / other
            for candidate in ["eth0", "ens33", "ens3", "enp0s3", "wlan0", "wlo1"]:
                if candidate in all_ifaces:
                    try:
                        ip = get_if_addr(candidate)
                        if ip and ip != "0.0.0.0":
                            print(f"[CAPTURE] Linux: selected interface {candidate} ({ip})")
                            return candidate
                    except Exception:
                        pass
            # Fallback: first non-loopback with IP
            for iface in all_ifaces:
                if iface == "lo":
                    continue
                try:
                    ip = get_if_addr(iface)
                    if ip and ip != "0.0.0.0":
                        print(f"[CAPTURE] Linux fallback: {iface} ({ip})")
                        return iface
                except Exception:
                    pass

    except Exception as e:
        print(f"[CAPTURE] Interface detection error: {e}")

    # Final fallback: scapy default
    fallback = str(conf.iface)
    print(f"[CAPTURE] Using scapy default interface: {fallback}")
    return fallback


INTERFACE = _detect_interface()
packets   = Queue()


def handle(pkt):
    packets.put(pkt)


def start_sniffer():
    print(f"[CAPTURE] Starting sniffer on interface: {INTERFACE}")
    try:
        sniff(iface=INTERFACE, prn=handle, store=False)
    except PermissionError:
        print("[CAPTURE] ❌ Permission denied — re-run with sudo")
    except Exception as e:
        print(f"[CAPTURE] ❌ Sniffer error: {e}")


sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
sniffer_thread.start()
print(f"[CAPTURE] Sniffer thread started on {INTERFACE} ✅")