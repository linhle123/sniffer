run the sniffer with (uncomment "import iptc" first):
sudo python3 traffic_manager.py <ip address> <action_code>

Action codes:
1 - drop incoming packets
2 - drop outgoing packets
3 - drop packets for both directions

or to do simple sniffing with no traffic blocking:
sudo python3 traffic_manager.py
