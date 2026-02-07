🦅 PacketHawk – Network Packet Sniffer

PacketHawk is a Python-based network packet sniffer designed to capture, analyze, and display low-level network traffic in real time.
The project focuses on understanding how data flows across networks by inspecting Ethernet frames, IPv4 packets, and common transport-layer protocols.

This tool is built as an educational and experimental project, emphasizing network fundamentals, protocol analysis, and cybersecurity concepts.

✨ Features

Captures live network traffic

Parses Ethernet frames

Decodes IPv4 packets

Identifies and analyzes:

ICMP packets

TCP segments

UDP datagrams

Displays source/destination MAC and IP addresses

Prints protocol-specific metadata (ports, flags, TTL, etc.)

🛠️ Technologies Used

Python 3

Scapy (cross-platform packet capture)

libpcap / Npcap (platform-dependent backend)

🖥️ Platform Support
Platform	Status
Linux (Kali / Ubuntu)	✅ Supported
Windows (Npcap required)	⚠️ Supported
macOS	⏳ Planned

⚠️ Administrative/root privileges are required to capture packets.


🚀 Getting Started
Clone the Repository
git clone https://github.com/MuhammadZaidSaqib/PacketHawk.git
cd PacketHawk


Install Dependencies
pip install scapy

Run the Sniffer

Linux

sudo python3 main.py


Windows (Run PowerShell as Administrator)

py main.py


Make sure Npcap is installed on Windows with “WinPcap compatibility mode” enabled.

📂 Project Structure
PacketHawk/
│
├── main.py        # Core packet sniffer logic
├── README.md      # Project documentation
└── .gitignore

🎯 Project Objective

The main goal of PacketHawk is to:

Strengthen understanding of network protocols

Explore how packet sniffers work internally

Apply cybersecurity concepts in a practical way

Serve as a foundation for more advanced network analysis tools

🔮 Future Enhancements

Interface selection support

Packet filtering (BPF)

Save captures to .pcap files

Protocol statistics dashboard

GUI-based packet visualization

IDS/IPS feature integration

⚠️ Disclaimer

This project is intended strictly for educational and ethical purposes.
Do not use PacketHawk on networks you do not own or have explicit permission to analyze.

👤 Author

Muhammad Zaid Saqib
Cybersecurity & Networking Enthusiast
GitHub: MuhammadZaidSaqib
