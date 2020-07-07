import re
import sys
from typing import Dict, List, Any

# Creating regular expressions (regex) to filter out the target log
INTERFACES_PATTERN = 'LINK-3-UPDOWN.*Interface\s([a-zA-Z]*[0-9]\/[0-9]+).*(down|up)'
INTERFACES_PATTERN_COMPILED = re.compile(INTERFACES_PATTERN)

BLOCKED_IP_ADDRESSES_PATTERN = 'SEC-6-IPACCESSLOGP.*denied\stcp\s([0-9.]+).*([0-9]+)'
BLOCKED_IP_ADDRESSES_PATTERN_COMPILED = re.compile(BLOCKED_IP_ADDRESSES_PATTERN)

SPAN_TREE_VLAN_PATTERN = 'SPANTREE-2-BLOCK_PVID_LOCAL.*(VLAN[0-9]+)'
SPAN_TREE_VLAN_PATTERN_COMPILED = re.compile(SPAN_TREE_VLAN_PATTERN)

BLOCKED_ICMP_PACKETS_PATTERN = 'SEC-6-IPACCESSLOGDP.*denied\sicmp\s.*([0-9]+)'
BLOCKED_ICMP_PACKETS_PATTERN_COMPILED = re.compile(BLOCKED_ICMP_PACKETS_PATTERN)


class LogAnalyzer:
    """
    A class that provides us with methods to:
        1) Analyse blocked TCP/IP addresses
        2) Analyse blocked ICMP packets
        3) Spanning tree problems caused by VLAN
        4) Analyse the change in network interfaces states (up or down)
    """
    def __init__(self, logs: List[str]):
        """
        :param logs: a list containing the log file data
        """
        self.logs = logs

    def analyze_network_interfaces(self):
        """
        :return top 5 network interfaces whose state was up, and top 5 interfaces whose state was down and how many times
        """
        interfaces_counter = {
            'up': {},
            'down': {},
        }

        # Create a generator to efficiently handle large data
        log_info = (line for line in self.logs)

        # Loop through each line in the log data and enforce the network interface regex
        for line in log_info:
            match = INTERFACES_PATTERN_COMPILED.search(line)
            if match is None:
                continue

            # Capture the first and second groups in the matched line
            # First group :  interface name
            # Second group:  state (up or down)
            interface_name = match.group(1)
            state = match.group(2)

            # If the interface name is already stored, then increment its state counter by 1
            if interface_name in list(interfaces_counter[state].keys()):
                interfaces_counter[state][interface_name] += 1
                continue

            # Otherwise, it's a new interface, so just store it
            interfaces_counter[state].update({interface_name: 1})

        # Sort the dictionary by value in a descending order
        interfaces_up = self.sort_dict_by_value(interfaces_counter['up'])
        interfaces_down = self.sort_dict_by_value(interfaces_counter['down'])

        return list(interfaces_up.items())[:5], list(interfaces_down.items())[:5]

    @staticmethod
    def sort_dict_by_value(data: Dict[str, Any]):
        """
        :param data: a dictionary of data counter of different network log statistics
        :return: a sorted dictionary by value (in a descending order)
        """
        return {
            source_ip: packets_blocked
            for source_ip, packets_blocked
            in sorted(
                data.items(),
                key=lambda packets: packets[1],
                reverse=True,
            )
        }

    def analyze_blocked_ip_addresses(self):
        """
        :return: top 20 blocked (denied) TCP/IP addresses and the total number of their packets
        """
        blocked_ip_address = {}
        # Python generator
        log_info = (line for line in self.logs)

        for line in log_info:
            match = BLOCKED_IP_ADDRESSES_PATTERN_COMPILED.search(line)
            if match is None:
                continue

            # First group : source IP address
            # Second group: number of packets denied
            source_ip = match.group(1)
            packets_blocked = int(match.group(2))

            if source_ip in blocked_ip_address:
                blocked_ip_address[source_ip] += packets_blocked
                continue

            blocked_ip_address.update({source_ip: packets_blocked})

        sorted_by_packets = self.sort_dict_by_value(blocked_ip_address)

        return list(sorted_by_packets.items())[:20]

    def analyze_spanning_tree_by_vlan(self):
        """
        :return: Inconsistent local VLAN causing spanning tree problems and how many times they occurred
        """
        span_tree_vlan = {}
        log_info = (line for line in self.logs)

        for line in log_info:
            match = SPAN_TREE_VLAN_PATTERN_COMPILED.search(line)
            if match is None:
                continue

            # First group: VLAN name
            vlan = match.group(1)

            if vlan in span_tree_vlan:
                span_tree_vlan[vlan] += 1
                continue

            span_tree_vlan.update({vlan: 1})

        sorted_span_tree_by_vlan = self.sort_dict_by_value(span_tree_vlan)
        return sorted_span_tree_by_vlan

    def analyze_blocked_icmp_packets(self):
        """
        :return: the total number of ICMP packets denied
        """
        blocked_icmp_packets = 0
        log_info = (line for line in self.logs)

        for line in log_info:
            match = BLOCKED_ICMP_PACKETS_PATTERN_COMPILED.search(line)
            if match is None:
                continue

            blocked_icmp_packets += int(match.group(1))

        return blocked_icmp_packets


if __name__ == '__main__':
    log_file = 'router1.log'

    # Open and read the log file
    try:
        with open(log_file, 'r') as file:
            logs = file.readlines()
    except FileNotFoundError as e:
        print(f'File not found {log_file}')
        sys.exit(1)

    analyzer = LogAnalyzer(logs)

    top_5_interfaces_up, top_5_interfaces_down = analyzer.analyze_network_interfaces()
    print('Top 5 Interfaces According to The Number of Downs\t\t\t\t:', top_5_interfaces_up)
    print('Top 5 Interfaces According to The Number of Ups\t\t\t\t\t:', top_5_interfaces_down)

    top_20_blocked_ip_Address = analyzer.analyze_blocked_ip_addresses()
    print('Top 20 Blocked IP Addresses and The Number of Their TCP Packets :', top_20_blocked_ip_Address)

    span_tree_by_vlan = analyzer.analyze_spanning_tree_by_vlan()
    print('Spanning Tree Problems By VLAN and Their Occurrences\t\t\t:', span_tree_by_vlan)

    blocked_icmp_packets = analyzer.analyze_blocked_icmp_packets()
    print('Total Number of Blocked ICMP Packets\t\t\t\t\t\t\t:', blocked_icmp_packets)
