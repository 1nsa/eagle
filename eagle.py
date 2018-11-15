#!/usr/bin/env python

import scapy.all as scapy
import optparse
import requests


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="IP of target to scan")
    options, _arguments = parser.parse_args()
    if not options.target:
        parser.error("Please specify a target to scan, use --help for more info.")
    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast_request = broadcast / arp_request
    answered_list = scapy.srp(arp_broadcast_request, timeout=2, verbose=False)[0]
    client_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list


def get_mac_vendor(list_of_clients):
    mac_url = "http://macvendors.co/api/%s"
    clients_and_mac_vendors = []
    for client in list_of_clients:
        r = requests.get(mac_url % client["mac"])
        clients_and_mac_vendors_dict = {"ip": client['ip'], "mac": client['mac'],
                                        "vendor": r.json()['result']['company']}
        clients_and_mac_vendors.append(clients_and_mac_vendors_dict)
    return clients_and_mac_vendors


def print_clients(list_of_clients):
    print("Clients Discovered: " + str(len(list_of_clients)) + "\n")
    print("IP Address\t\t\tMAC Address\t\t\tVendor")
    print("--------------------------------------------------------------------------------------------")
    for client in list_of_clients:
        print(client["ip"] + "\t\t\t" + client["mac"] + "\t\t" + client["vendor"])


arguments = get_arguments()
clients = scan(arguments.target)
clients_and_vendors = get_mac_vendor(clients)
print_clients(clients_and_vendors)
