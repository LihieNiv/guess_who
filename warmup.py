import pyshark


class AnalyzeNetwork:
    FORBIDDEN_MAC = {"ff:ff:ff:ff:ff:ff"}
    FORBIDDEN_IP = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}

    def __init__(self, pcap_path):
        self.pcap_path = pcap_path
        self.ip_dict = {}
        self.mac_dict = {}
        try:
            self.pcap_file = pyshark.FileCapture(pcap_path)
        except Exception:
            raise ValueError("Bad pcap_file")
        for packet in self.pcap_file:
            src_mac = packet.eth.src
            dst_mac = packet.eth.dst
            src_ven = "UNKNOWN"
            dst_ven = "UNKNOWN"
            try:
                src_ven = packet.eth._all_fields["eth.src.oui_resolved"]
            except Exception:
                y = 1
            try:
                dst_ven = packet.eth._all_fields["eth.dst.oui_resolved"]
            except Exception:
                y = 2
            src_ip = "UNKNOWN"
            dst_ip = "UNKNOWN"
            if "IP" in packet:
                src_ip = packet.ip._all_fields["ip.src.addr"]
                dst_ip = packet.ip._all_fields["ip.dst.addr"]
            if "ARP" in packet:
                src_ip = packet.arp._all_fields["arp.src.proto_ipv4"]
                dst_ip = packet.arp._all_fields["arp.dst.proto_ipv4"]
            src_info = {"MAC": src_mac, "IP": src_ip, "VENDOR": src_ven}
            dst_info = {"MAC": dst_mac, "IP": dst_ip, "VENDOR": dst_ven}
            if (
                src_ip not in AnalyzeNetwork.FORBIDDEN_IP
                and src_mac not in AnalyzeNetwork.FORBIDDEN_MAC
            ):
                if src_mac not in self.mac_dict:
                    self.mac_dict[src_mac] = {}
                if src_ip not in self.ip_dict:
                    self.ip_dict[src_ip] = {}
                self.mac_dict[src_mac][src_ip] = src_info
                self.ip_dict[src_ip][src_mac] = src_info
            if (
                dst_ip not in AnalyzeNetwork.FORBIDDEN_IP
                and dst_mac not in AnalyzeNetwork.FORBIDDEN_MAC
            ):
                if dst_mac not in self.mac_dict:
                    self.mac_dict[dst_mac] = {}
                if dst_ip not in self.ip_dict:
                    self.ip_dict[dst_ip] = {}
                self.ip_dict[dst_ip][dst_mac] = dst_info
                self.mac_dict[dst_mac][dst_ip] = dst_info

    def get_ips(self):
        """Returns list of ip addresses (strings) in pcap file."""
        return list(self.ip_dict.keys())

    def get_macs(self):
        """Returns list of MAC addresses (strings) in pcap file."""
        return list(self.mac_dict.keys())

    def get_items(self, my_dict: dict):
        ret = []
        for key, item in my_dict.items():
            ret.append(item)
        return ret

    def get_info_by_mac(self, mac):
        """Returns a dict with all information about the device with given MAC address."""
        if mac not in self.mac_dict:
            raise KeyError("Unrecognized MAC address")
        return self.get_items(self.mac_dict[mac])

    def get_info_by_ip(self, ip):
        """Returns a dict with all information about the device with given ip address."""
        if ip not in self.ip_dict:
            raise KeyError("Unrecognized IP address")
        return self.get_items(self.ip_dict[ip])

    def get_info(self):
        """Returns a list of dicts with information about every device in the pcap"""
        all_mac = self.get_macs()
        info_by_mac = [self.get_info_by_mac(mac) for mac in all_mac]
        return info_by_mac

    def __repr__(self):
        return f"<Network Analyzer For File:'{self.pcap_path}'>"

    def __str__(self):
        return f"Network Analyzer For File: '{self.pcap_path}'"
