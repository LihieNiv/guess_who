import pyshark

UNKNOWN = "UNKNOWN"
UNIX = "UNIX"
WINDOWS = "WINDOWS"
SOLARIS = "SOLARIS"


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
        self._load_data()

    def infer_os(self, packet):
        if "ICMP" not in packet:
            return UNKNOWN
        ttl = int(packet.ip.ttl)
        if ttl <= 64:
            return UNIX
        if ttl <= 128:
            return WINDOWS
        return SOLARIS

    def parse_time_zone(self, time_zone):
        i = len(time_zone) - 1
        nums = [str(j) for j in range(10)]
        while i >= 0 and time_zone[i] not in nums:
            i -= 1
        i += 2
        return time_zone[i:]

    def get_time_zone(self, packet):
        if (
            "ICMP" not in packet
            or "icmp.data_time" not in packet.icmp._all_fields
            or packet.icmp.type != "8"
        ):
            return UNKNOWN
        return self.parse_time_zone(packet.icmp.data_time)

    def get_vendor(self, packet, type):
        try:
            ven = packet.eth._all_fields["eth." + type + ".oui_resolved"]
            return ven
        except Exception:
            return UNKNOWN

    def guess_os(self, info_dict):
        return info_dict["OPERATING SYSTEM"]

    def get_ip_from_packet(self, packet, type):
        if "IP" in packet:
            ip = packet.ip._all_fields["ip." + type]
            return ip
        if "ARP" in packet:
            ip = packet.arp._all_fields["arp." + type + ".proto_ipv4"]
            return ip
        return UNKNOWN

    def merge_dicts(self, old, new):
        old_keys = old.keys()
        for key in new.keys():
            if key not in old_keys or new[key] != UNKNOWN:
                old[key] = new[key]

    def _add_to_dict(self, info):
        ip = info["IP"]
        mac = info["MAC"]
        if (
            ip not in AnalyzeNetwork.FORBIDDEN_IP
            and mac not in AnalyzeNetwork.FORBIDDEN_MAC
        ):
            if mac not in self.mac_dict:
                self.mac_dict[mac] = {}
            if ip not in self.ip_dict:
                self.ip_dict[ip] = {}
            if ip not in self.mac_dict[mac]:
                self.mac_dict[mac][ip] = {}
            if mac not in self.ip_dict[ip]:
                self.ip_dict[ip][mac] = {}
            self.merge_dicts(self.mac_dict[mac][ip], info)
            self.merge_dicts(self.ip_dict[ip][mac], info)

    def _load_data(self):
        for packet in self.pcap_file:
            src_mac = packet.eth.src
            dst_mac = packet.eth.dst
            src_ven = self.get_vendor(packet, "src")
            dst_ven = self.get_vendor(packet, "dst")
            src_ip = self.get_ip_from_packet(packet, "src")
            dst_ip = self.get_ip_from_packet(packet, "dst")
            src_op = self.infer_os(packet)
            dst_op = UNKNOWN
            src_TZ = self.get_time_zone(packet)
            dst_TZ = UNKNOWN
            src_info = {
                "MAC": src_mac,
                "IP": src_ip,
                "VENDOR": src_ven,
                "OPERATING SYSTEM": src_op,
                "TIME ZONE": src_TZ,
            }
            dst_info = {
                "MAC": dst_mac,
                "IP": dst_ip,
                "VENDOR": dst_ven,
                "OPERATING SYSTEM": dst_op,
                "TIME ZONE": dst_TZ,
            }
            self._add_to_dict(src_info)
            self._add_to_dict(dst_info)

    def get_ips(self):
        """Returns list of ip addresses (strings) in pcap file."""
        lst = list(self.ip_dict.keys())
        lst.remove(UNKNOWN)
        return lst

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
        if ip not in self.ip_dict or ip == UNKNOWN:
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
