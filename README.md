Features 
--------

1. Multi-Layer Protocol Analysis
    ----------------------------
    Supports analysis from Layer 2 (Ethernet) to Layer 7 (Application)
    Handles common protocols: Ethernet, IP, TCP, UDP, ICMP, ARP
    Application layer analysis for HTTP, DNS, DHCP, etc.

2. Comprehensive Packet Inspection
   -------------------------------
    Deep packet inspection of headers and payloads
    TCP flag analysis (SYN, ACK, FIN, RST, etc.)
    UDP port-based service identification
    Payload extraction and display (first 200 chars)

3. Anomaly Detection Capabilities
   ------------------------------
    Detects port scans (SYN scans, NULL scans)
    Identifies IP fragmentation anomalies
    Flags suspicious TCP window sizes and options
    Detects unusually large ICMP packets (Ping of Death)
    Identifies low TTL values and IP options

4. Statistical Tracking
   --------------------
    Real-time packet counting
    Protocol distribution statistics
    Packets-per-second calculation
    Periodic summary display (every 50 packets)

5. Flexible Output Options
   -----------------------
    Console output (standard and verbose modes)
    File logging capability
    JSON format support for structured data
    Timestamped records

6. Customizable Capture
   --------------------
    BPF filter support (tcpdump-style filters)
    Interface selection
    Packet count limitation
    Verbose mode for detailed output

7. Performance Considerations
   --------------------------
    Non-storage mode (store=0) for memory efficiency
    Graceful shutdown handling
    Real-time processing without packet storage

8. Security Features
   -----------------
    Requires elevated privileges (ethical use)
    Clean shutdown on interrupt
    Error handling for malformed packets

9. Educational Value
   -----------------
    Demonstrates OSI model layers in practice
    Shows common network attack patterns
    Illustrates protocol interactions
    Provides hands-on packet analysis experience

10. Technical Specifications
    ------------------------
    Python 3.6+ compatible
    Scapy as core dependency
    Cross-platform (Linux/Windows/macOS)
    Single-file implementation
    No database requirements

11. Use Case Scenarios
    ------------------
    Network troubleshooting
    Security monitoring
    Protocol learning and analysis
    Network traffic visualization (when combined with other tools)
    Incident investigation

12. Ethical Design
    --------------
    Explicit interface selection
    Requires user-specified filters
    Clear output labeling
    No hidden data collection
