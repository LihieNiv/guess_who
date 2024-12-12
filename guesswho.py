import pyshark

UNKNOWN = "UNKNOWN"
UNIX = "UNIX"
WINDOWS = "WINDOWS"
SOLARIS = "SOLARIS"


class AnalyzeNetwork:
    FORBIDDEN_MAC = {"ff:ff:ff:ff:ff:ff"}
    FORBIDDEN_IP = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}
    BROWSERS = {
        "Firefox": [{"Firefox"}, {"Seamonkey"}],
        "Seamonkey": [{"Seamonkey"}, {}],
        "Chrome": [{"Chrome"}, {"Chromium", "Edg"}],
        "Chromium": [{"Chromium"}, {}],
        "Safari": [{"Safari"}, {"Chrome", "Chromium"}],
        "Edge": [{"Edg"}, {}],
        "Opera 15+": [{"OPR"}, {}],
        "Opera 12-": [{"Opera"}, {}],
    }

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
        if "IP" not in packet:
            return UNKNOWN
        ttl = int(packet.ip.ttl)
        if ttl <= 64:
            if "ICMP" not in packet:
                return UNIX
            if "icmp.data_time" in packet.icmp._all_fields:
                return UNIX
        if ttl <= 128:
            return WINDOWS
        return SOLARIS

    def infer_protocol(self, packet, protocol):
        layers = [repr(item)[1:-7] for item in packet.layers]
        ind = layers.index(protocol)
        if ind == len(layers) - 1:
            return UNKNOWN
        if layers[ind + 1] == "DATA":
            if ind + 1 == len(layers) - 1:
                return "DATA"
            return layers[ind + 2]
        return layers[ind + 1]

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
            if isinstance(new[key], dict):
                if key not in old_keys:
                    old[key] = new[key]
                else:
                    self.merge_dicts(old[key], new[key])
            elif key not in old_keys or new[key] != UNKNOWN:
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

    def find_protocol(self, packet):
        if "TCP" in packet:
            sport = packet.tcp.port
            dport = packet.tcp.dstport
            protocol = self.infer_protocol(packet, "TCP")
            sprotocol = protocol
            if protocol == "HTTP":
                browser = self.get_browser_name(packet)
                sprotocol = (protocol, browser)
            return {sport: sprotocol}, {dport: protocol}
        elif "UDP" in packet:
            sport = packet.udp.port
            dport = packet.udp.dstport
            protocol = self.infer_protocol(packet, "UDP")
            return {sport: protocol}, {dport: protocol}
        return {}, {}

    def get_http_url(self, packet):
        if "HTTP" not in packet:
            return UNKNOWN
        if (
            "http.request" not in packet.http._all_fields
            or packet.http.request != "True"
        ):
            return UNKNOWN
        return packet.http._all_fields["http.request.uri"]

    def get_browser_name(self, packet):
        if "HTTP" not in packet or "http.user_agent" not in packet.http._all_fields:
            return UNKNOWN
        user_agent = packet.http.user_agent
        for browser in self.BROWSERS:
            flag = True
            l = self.BROWSERS[browser]
            for good in l[0]:
                if good not in user_agent:
                    flag = False
            for bad in l[1]:
                if bad in user_agent:
                    flag = False
            if flag:
                return browser
        return UNKNOWN

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
            src_prot_dict, dst_prot_dict = self.find_protocol(packet)
            src_info = {
                "MAC": src_mac,
                "IP": src_ip,
                "VENDOR": src_ven,
                "OPERATING SYSTEM": src_op,
                "TIME ZONE": src_TZ,
                "PORT-PROTO DICT": src_prot_dict,
            }
            dst_info = {
                "MAC": dst_mac,
                "IP": dst_ip,
                "VENDOR": dst_ven,
                "OPERATING SYSTEM": dst_op,
                "TIME ZONE": dst_TZ,
                "PORT-PROTO DICT": dst_prot_dict,
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


if __name__ == "__main__":
    # Probably something with how pyshark opens the file but you need to call this from the same directory as where the file is.
    path = "pcap-03.pcapng"
    anlz = AnalyzeNetwork(path)
    print(anlz.get_info())
