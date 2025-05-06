#!/usr/bin/env python3
from scapy.all import *
import argparse
import json
from datetime import datetime
import sys
import signal

class AdvancedPacketSniffer:
    def __init__(self):
        self.packet_count = 0
        self.protocol_stats = {}
        self.start_time = None
        self.capture_filter = None
        self.output_file = None
        self.json_output = False
        self.verbose = False
        self.running = False

    def process_packet(self, packet):
        if not self.running:
            return
        
        self.packet_count += 1
        
        # Protocol analysis
        self.analyze_protocols(packet)
        
        # Packet details
        if self.verbose:
            self.display_packet_details(packet)
        
        # Anomaly detection
        self.detect_anomalies(packet)
        
        # Output handling
        if self.output_file:
            self.write_to_file(packet)
        
        # Print summary periodically
        if self.packet_count % 50 == 0:
            self.print_stats()

    def analyze_protocols(self, packet):
        # Ethernet layer
        if Ether in packet:
            eth = packet[Ether]
            self.update_stats('Ethernet', eth)
            
            # IP layer
            if IP in packet:
                ip = packet[IP]
                self.update_stats('IP', ip)
                
                # Transport layer protocols
                if TCP in packet:
                    tcp = packet[TCP]
                    self.update_stats('TCP', tcp)
                    self.analyze_tcp(tcp)
                elif UDP in packet:
                    udp = packet[UDP]
                    self.update_stats('UDP', udp)
                    self.analyze_udp(udp)
                elif ICMP in packet:
                    icmp = packet[ICMP]
                    self.update_stats('ICMP', icmp)
                
                # Application layer
                self.analyze_application_layer(packet)
            
            elif ARP in packet:
                arp = packet[ARP]
                self.update_stats('ARP', arp)

    def analyze_tcp(self, tcp):
        # Analyze TCP flags
        flags = []
        if tcp.flags & 0x01: flags.append("FIN")
        if tcp.flags & 0x02: flags.append("SYN")
        if tcp.flags & 0x04: flags.append("RST")
        if tcp.flags & 0x08: flags.append("PSH")
        if tcp.flags & 0x10: flags.append("ACK")
        if tcp.flags & 0x20: flags.append("URG")
        if tcp.flags & 0x40: flags.append("ECE")
        if tcp.flags & 0x80: flags.append("CWR")
        
        if self.verbose:
            print(f"TCP Flags: {', '.join(flags)}")
        
        # Detect SYN scans
        if "SYN" in flags and not "ACK" in flags:
            self.update_stats('TCP_SYN_SCAN', 1)
        
        # Detect NULL scans
        if tcp.flags == 0:
            self.update_stats('TCP_NULL_SCAN', 1)
    
    def analyze_udp(self, udp):
        # Common UDP ports analysis
        common_ports = {
            53: "DNS",
            67: "DHCP Server",
            68: "DHCP Client",
            69: "TFTP",
            123: "NTP",
            161: "SNMP",
            162: "SNMP Trap",
            514: "Syslog"
        }
        
        if udp.dport in common_ports or udp.sport in common_ports:
            port = udp.dport if udp.dport in common_ports else udp.sport
            self.update_stats(f"UDP_{common_ports[port]}", 1)
    
    def analyze_application_layer(self, packet):
        # DNS analysis
        if packet.haslayer(DNS):
            self.update_stats('DNS', 1)
            dns = packet[DNS]
            if dns.qr == 0:  # DNS query
                if dns.qd:
                    self.update_stats('DNS_QUERY', str(dns.qd.qname))
            else:  # DNS response
                if dns.an:
                    for answer in dns.an:
                        if answer.type == 1:  # A record
                            self.update_stats('DNS_RESPONSE_A', str(answer.rdata))
        
        # HTTP analysis
        if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                if "HTTP" in payload:
                    self.update_stats('HTTP', 1)
                    if "GET" in payload:
                        self.update_stats('HTTP_GET', 1)
                        # Extract URL
                        lines = payload.split('\r\n')
                        for line in lines:
                            if line.startswith('GET'):
                                url = line.split(' ')[1]
                                self.update_stats('HTTP_URL', url)
                                break

    def detect_anomalies(self, packet):
        # IP fragmentation anomalies
        if IP in packet:
            if packet[IP].flags & 0x1 or packet[IP].frag != 0:  # MF flag set or frag offset
                self.update_stats('IP_FRAGMENTATION', 1)
            
            # TTL anomalies
            if packet[IP].ttl < 32:
                self.update_stats('LOW_TTL', 1)
            
            # Suspicious IP options
            if packet[IP].options:
                self.update_stats('IP_OPTIONS', 1)
        
        # TCP anomalies
        if TCP in packet:
            tcp = packet[TCP]
            # TCP window size anomaly
            if tcp.window == 0:
                self.update_stats('TCP_ZERO_WINDOW', 1)
            elif tcp.window < 1024:
                self.update_stats('TCP_SMALL_WINDOW', 1)
            
            # TCP options analysis
            if tcp.options:
                for opt in tcp.options:
                    if opt[0] == 'MSS':
                        if opt[1] < 536:  # Unusually small MSS
                            self.update_stats('TCP_SMALL_MSS', 1)
        
        # Large ICMP packets (possible ping of death)
        if ICMP in packet and len(packet) > 1024:
            self.update_stats('LARGE_ICMP', 1)

    def update_stats(self, key, value):
        if key not in self.protocol_stats:
            self.protocol_stats[key] = 0
        self.protocol_stats[key] += 1
    
    def print_stats(self):
        print(f"\n[+] Packet Count: {self.packet_count}")
        print("[+] Protocol Statistics:")
        for proto, count in sorted(self.protocol_stats.items()):
            print(f"    {proto}: {count}")
        
        # Calculate packets per second
        if self.start_time:
            elapsed = (datetime.now() - self.start_time).total_seconds()
            print(f"[+] Packets per second: {self.packet_count/elapsed:.2f}")
    
    def display_packet_details(self, packet):
        print(f"\n[+] Packet #{self.packet_count}")
        print(packet.summary())
        
        # Show more details for specific protocols
        if packet.haslayer(TCP):
            print(f"    TCP: {packet[TCP].sport} -> {packet[TCP].dport}")
            print(f"    Seq: {packet[TCP].seq}, Ack: {packet[TCP].ack}")
        
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                print("    Payload:")
                print(payload[:200])  # Print first 200 chars
            except:
                pass
    
    def write_to_file(self, packet):
        with open(self.output_file, 'a') as f:
            if self.json_output:
                packet_dict = {
                    'timestamp': datetime.now().isoformat(),
                    'summary': packet.summary(),
                    'layers': {}
                }
                
                for layer in packet.layers():
                    layer_name = layer.__name__
                    packet_dict['layers'][layer_name] = {}
                    for field in packet[layer].fields_desc:
                        packet_dict['layers'][layer_name][field.name] = getattr(packet[layer], field.name)
                
                f.write(json.dumps(packet_dict) + '\n')
            else:
                f.write(f"{datetime.now()} - {packet.summary()}\n")

    def start_capture(self, interface=None, count=0):
        self.running = True
        self.start_time = datetime.now()
        
        print(f"[+] Starting packet capture on {interface or 'all interfaces'}")
        print("[+] Press Ctrl+C to stop")
        
        try:
            sniff(
                iface=interface,
                prn=self.process_packet,
                count=count,
                filter=self.capture_filter,
                store=0
            )
        except KeyboardInterrupt:
            print("\n[!] Capture stopped by user")
        except Exception as e:
            print(f"[!] Error: {e}")
        finally:
            self.running = False
            self.print_final_stats()
    
    def print_final_stats(self):
        print("\n[+] Capture Summary:")
        print(f"    Total packets: {self.packet_count}")
        print(f"    Duration: {(datetime.now() - self.start_time).total_seconds():.2f} seconds")
        print(f"    Packets/sec: {self.packet_count/(datetime.now() - self.start_time).total_seconds():.2f}")
        
        print("\nProtocol Distribution:")
        for proto, count in sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True):
            print(f"    {proto}: {count} ({count/self.packet_count*100:.1f}%)")

def parse_args():
    parser = argparse.ArgumentParser(description="Advanced Packet Sniffer")
    parser.add_argument('-i', '--interface', help="Network interface to capture on")
    parser.add_argument('-f', '--filter', help="BPF filter to apply")
    parser.add_argument('-c', '--count', type=int, default=0, help="Number of packets to capture (0 for unlimited)")
    parser.add_argument('-o', '--output', help="Output file to save packets")
    parser.add_argument('-j', '--json', action='store_true', help="Output in JSON format")
    parser.add_argument('-v', '--verbose', action='store_true', help="Verbose output")
    return parser.parse_args()

def main():
    args = parse_args()
    
    sniffer = AdvancedPacketSniffer()
    sniffer.capture_filter = args.filter
    sniffer.output_file = args.output
    sniffer.json_output = args.json
    sniffer.verbose = args.verbose
    
    # Handle graceful shutdown
    def signal_handler(sig, frame):
        print("\n[!] Shutting down...")
        sniffer.running = False
        sniffer.print_final_stats()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    sniffer.start_capture(interface=args.interface, count=args.count)

if __name__ == "__main__":
    main()