''' Prologue Comments 
Artifact: Metadata_extraction.py
Description: Runs continuous packet sniffing, extracts packet metadata, and forwards to cloud storage.
Programmer's name: Aryan Vinod Ghorpade
Creation Date: 2/12/2026
Revision Dates:
    2/15/2026: Revised to allow virtual environment to run.
    2/15/2026: Updated to include cloud forwader functionality.
Preconditions:
    Currently no direct user inputs. Network traffic picked up on the machine is obtained automatically.
Postconditions:
    Returns status of packet capture, metadata, and success/failure of the forwarder to the cloud.
    Creates database for packets on machine if not present, otherwise writes to the database.
Errors/Exceptions:
    Errors can occur at packet forwarding step depending on whether or not AWS services are available.
        For instance, Error 500. Or if the invoked API URL is wrong, Error 404.
Side effects: none
Invariants: none
'''

from scapy.all import IP, TCP, UDP
from database import PacketDatabase
import capture_packet as capture_packet
from datetime import datetime
from forward_to_cloud import forward_metadata

def extract_metadata(packet):
    metadata = {}
    #gives us the time and date of the packet capture as (DD/MM/YYYY HH:MM:SS)
    metadata['timestamp'] = datetime.fromtimestamp(packet.time).strftime('%d/%m/%Y -- %H:%M:%S')

    # Check if packet has IP layer
    if IP in packet:
        metadata['src_ip'] = packet[IP].src
        metadata['dst_ip'] = packet[IP].dst
    else:
        return None
    
    # Check for TCP or UDP layer
    if TCP in packet:
        metadata['src_port'] = packet[TCP].sport
        metadata['dst_port'] = packet[TCP].dport
        metadata['protocol'] = 'TCP'
    elif UDP in packet:
        metadata['src_port'] = packet[UDP].sport
        metadata['dst_port'] = packet[UDP].dport
        metadata['protocol'] = 'UDP'
    else:
        metadata['src_port'] = None
        metadata['dst_port'] = None
        metadata['protocol'] = packet[IP].proto
    
    return metadata

def main():
    db = PacketDatabase()
    
    try:
        while True:
            packet = capture_packet.packets.get()
            metadata = extract_metadata(packet)
            if metadata:
                forward_metadata(metadata)
                db.insert_metadata(metadata)
                print(f"Stored: {metadata}")
    except KeyboardInterrupt:
        print("Stopping...")
    finally:
        db.close()

if __name__ == "__main__":
    main()
