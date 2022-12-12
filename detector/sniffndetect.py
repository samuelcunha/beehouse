import os
import sys
import ctypes
import threading
from scapy.all import *
from datetime import datetime
from queue import Queue

banner = '''-----------------------
SniffnDetect v.1.1
-----------------------
'''

class SniffnDetect():
    def __init__(self):
        self.INTERFACE = conf.iface
        self.MY_IP = [x[4] for x in conf.route.routes if x[2]
                      != '0.0.0.0' and x[3] == self.INTERFACE][0]
        self.MY_MAC = get_if_hwaddr(self.INTERFACE)
        self.WEBSOCKET = None
        self.PACKETS_QUEUE = Queue()
        self.MAC_TABLE = {}
        self.RECENT_ACTIVITIES = []
        self.FILTERED_ACTIVITIES = {
            'TCP-SYN': {'flag': False, 'activities': [], 'attacker-mac': [], 'attacker-ip': []},
            'TCP-SYNACK': {'flag': False, 'activities': [], 'attacker-mac': [], 'attacker-ip': []},
            'ICMP-POD': {'flag': False, 'activities': [], 'attacker-mac': [], 'attacker-ip': []},
            'ICMP-SMURF': {'flag': False, 'activities': [], 'attacker-mac': [], 'attacker-ip': []},
        }
        self.flag = False
        self.previousFlag = False
        self.attackTimestamp = None

        f = open("attackers.log", "w")
        f.write("")
        f.close()

        f = open("attacks.log", "w")
        f.write("")
        f.close()

    def sniffer_threader(self):
        while self.flag:
            pkt = sniff(count=1)
            with threading.Lock():
                self.PACKETS_QUEUE.put(pkt[0])

    def analyze_threader(self):
        while self.flag:
            pkt = self.PACKETS_QUEUE.get()
            self.analyze_packet(pkt)
            self.PACKETS_QUEUE.task_done()

    def check_avg_time(self, activities):
        time = 0
        c = -1
        while c > -21:
            time += activities[c][0] - activities[c-1][0]
            c -= 1
        time /= len(activities)
        return (time < 2 and self.RECENT_ACTIVITIES[-1][0] - activities[-1][0] < 10)

    def find_attackers(self, category):
        data = []
        for mac in self.FILTERED_ACTIVITIES[category]['attacker-mac']:
            data.append(
                f"({self.MAC_TABLE[mac]}, {mac})" if mac in self.MAC_TABLE else f"(Unknown IP, {mac})")
        f = open("attackers.log", "a")
        for ip in self.FILTERED_ACTIVITIES[category]['attacker-ip']:
            data.append(f"{ip}")
            f.write(f"{ip}\n")
        f.close()
        return category + ' Attackers :<br>' + "<br>".join(data) + '<br><br>'

    def set_flags(self):
        for category in self.FILTERED_ACTIVITIES:
            if len(self.FILTERED_ACTIVITIES[category]['activities']) > 20:
                inAttack = self.check_avg_time(
                    self.FILTERED_ACTIVITIES[category]['activities'])
                self.FILTERED_ACTIVITIES[category]['flag'] = inAttack
                now = datetime.now()
                if inAttack:
                    if not self.previousFlag:
                        self.previousFlag = True
                        self.attackTimestamp = now
                        f = open("attacks.log", "a")
                        startTime = now.strftime("%Y-%m-%d %H:%M:%S")
                        f.write(f"ATTACK - START:  {startTime}\n")
                        f.close()
                    self.FILTERED_ACTIVITIES[category]['attacker-ip'] = list(
                        set([i[1] for i in self.FILTERED_ACTIVITIES[category]['activities']]))
                else:
                    if self.previousFlag:
                        self.previousFlag = False
                        endTime = now.strftime("%Y-%m-%d %H:%M:%S")
                        duration = now - self.attackTimestamp
                        f = open("attacks.log", "a")
                        f.write(f"ATTACK - END:  {endTime} - {duration}\n\n")
                        f.close()
                        self.find_attackers('TCP-SYN')
                        self.find_attackers('TCP-SYNACK')
                        self.find_attackers('ICMP-POD')
                        self.find_attackers('ICMP-SMURF')

    def analyze_packet(self, pkt):
        src_ip, dst_ip, src_port, dst_port, tcp_flags, icmp_type = None, None, None, None, None, None
        protocol = []

        if len(self.RECENT_ACTIVITIES) > 15:
            self.RECENT_ACTIVITIES = self.RECENT_ACTIVITIES[-15:]

        for category in self.FILTERED_ACTIVITIES:
            if len(self.FILTERED_ACTIVITIES[category]['activities']) > 30:
                self.FILTERED_ACTIVITIES[category]['activities'] = self.FILTERED_ACTIVITIES[category]['activities'][-30:]

        self.set_flags()

        src_mac = pkt[Ether].src if Ether in pkt else None
        dst_mac = pkt[Ether].dst if Ether in pkt else None

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst

        if TCP in pkt:
            protocol.append("TCP")
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            tcp_flags = pkt[TCP].flags.flagrepr()
        if UDP in pkt:
            protocol.append("UDP")
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        if ICMP in pkt:
            protocol.append("ICMP")
            # 8 for echo-request and 0 for echo-reply
            icmp_type = pkt[ICMP].type

        if ARP in pkt and pkt[ARP].op in (1, 2):
            protocol.append("ARP")
            if pkt[ARP].hwsrc in self.MAC_TABLE.keys() and self.MAC_TABLE[pkt[ARP].hwsrc] != pkt[ARP].psrc:
                self.MAC_TABLE[pkt[ARP].hwsrc] = pkt[ARP].psrc
            if pkt[ARP].hwsrc not in self.MAC_TABLE.keys():
                self.MAC_TABLE[pkt[ARP].hwsrc] = pkt[ARP].psrc

        load_len = len(pkt[Raw].load) if Raw in pkt else None

        attack_type = None

        if ICMP in pkt:
            if src_ip == self.MY_IP:
                self.FILTERED_ACTIVITIES['ICMP-SMURF']['activities'].append([
                                                                            pkt.time, ])
                attack_type = 'ICMP-SMURF PACKET'

            if load_len and load_len > 1024:
                self.FILTERED_ACTIVITIES['ICMP-POD']['activities'].append([
                                                                          pkt.time, ])
                attack_type = 'ICMP-PoD PACKET'

        if dst_ip == self.MY_IP:
            if TCP in pkt:
                if tcp_flags == "S":
                    self.FILTERED_ACTIVITIES['TCP-SYN']['activities'].append([
                                                                             pkt.time, pkt.sprintf("%IP.src%"), ])
                    attack_type = 'TCP-SYN PACKET'

                elif tcp_flags == "SA":
                    self.FILTERED_ACTIVITIES['TCP-SYNACK']['activities'].append([
                                                                                pkt.time, pkt.sprintf("%IP.src%"), ])
                    attack_type = 'TCP-SYNACK PACKET'

        self.RECENT_ACTIVITIES.append(
            [pkt.time, protocol, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, load_len, attack_type])

    def start(self):
        if not self.flag:
            self.flag = True
            sniff_thread = threading.Thread(target=self.sniffer_threader)
            sniff_thread.daemon = True
            sniff_thread.start()
            analyze_thread = threading.Thread(target=self.analyze_threader)
            analyze_thread.daemon = True
            analyze_thread.start()
        return self.flag

    def stop(self):
        self.flag = False
        self.PACKETS_QUEUE = Queue()
        self.RECENT_ACTIVITIES = []
        self.FILTERED_ACTIVITIES = {
            'TCP-SYN': {'flag': False, 'activities': [], 'attacker-mac': []},
            'TCP-SYNACK': {'flag': False, 'activities': [], 'attacker-mac': []},
            'ICMP-POD': {'flag': False, 'activities': [], 'attacker-mac': []},
            'ICMP-SMURF': {'flag': False, 'activities': [], 'attacker-mac': []},
        }
        return self.flag


def clear_screen():
    if "linux" in sys.platform:
        os.system("clear")
    elif "win32" in sys.platform:
        os.system("cls")
    else:
        pass


def is_admin():
    try:
        return os.getuid() == 0
    except AttributeError:
        pass
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() == 1
    except AttributeError:
        return False
