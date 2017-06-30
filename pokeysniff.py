#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import sys
import time
import signal
from struct import unpack

import argparse
this = sys.modules[__name__]

def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument('--filter', nargs='?', help='filter packets by type',
                        choices=['tcp','udp','icmp'])
    parser.add_argument('--src_port', type=int, help='specify a source port to monitor')
    parser.add_argument('--dest_port', type=int, help='specify a destination port to monitor')
    parser.add_argument('--nocolor', action='store_true', help='Skip colors in output')
    return parser.parse_args()

def mac_addr(addr):
    # Takes a list of mac addr components
    return ':'.join(['{:02x}'.format(a) for a in addr])

def cprint(val, col=None):
    if col==None:
        print(val, flush=True)
    print(color_wrap(val, col), flush=True)

def color_wrap(val, col):
    if args.nocolor:
        return str(val)
    return ''.join([col, str(val), Color.END])


class InterruptHandler:

    ''' Interrupt Handler as context manager '''

    def __init__(self, sig=signal.SIGINT):
        self.sig = sig

    def __enter__(self):
        self.interrupted = False
        self.released = False
        self.sig_orig = signal.getsignal(self.sig)

        def handler(signum, frame):
            self.release()
            self.interrupted = True

        signal.signal(self.sig, handler)
        return self

    def __exit__(self, type, value, tb):
        self.release()

    def release(self):
        if self.released:
            return False
        signal.signal(self.sig, self.sig_orig)
        self.released = True
        return True


class Color:
    BLACK_ON_GREEN = '\x1b[1;30;42m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    MSG = '\x1b[1;32;44m'
    ERR = '\x1b[1;31;44m'
    TST = '\x1b[7;34;46m'


class Packet:

    # Static header lengths
    eth_len = 14
    icmph_len = 3
    udph_len = 8

    # packet type constants
    TCP = 6
    UDP = 17
    ICMP = 1
    IP = 8
    OTH = 0

    def __init__(self, raw):
        self.protocol = 0
        self.raw = raw
        self.parse_eth()
        self._info_cache = False
        if self.ip_packet:
            self.parse_ip()
            if self.protocol == 1:
                self.parse_icmp()
            elif self.protocol == 6:
                self.parse_tcp()
            elif self.protocol == 17:
                self.parse_udp()

    def info(self):
        print('\nETH  :: eprotocol = {} | source MAC = {} | destination MAC = {} |'.format(
            color_wrap(self.eprot, Color.GREEN),
            color_wrap(self.source_mac, Color.GREEN),
            color_wrap(self.destination_mac, Color.CYAN)))
        if not self.ip_packet:
            cprint('[!] Not an IP packet', Color.MSG)
            return
        else:
            print('IP   :: version = {} | ttl = {} | protocol = {} | source IP = {} | destination IP = {} |'.format(
                color_wrap(self.version, Color.BLUE),
                color_wrap(self.ttl, Color.YELLOW),
                color_wrap(self.protocol, Color.YELLOW),
                color_wrap(self.src_addr, Color.GREEN),
                color_wrap(self.dest_addr, Color.CYAN)))
        if self.protocol not in [Packet.ICMP, Packet.TCP, Packet.UDP]:
            cprint('[!] Unknown Packet Type', Color.MSG)
            return
        else:
            if self.protocol == Packet.ICMP:
                print('ICMP :: type = {} | code = {} | checksum = {} |'.format(
                    color_wrap(self.icmp_type, Color.GREEN),
                    color_wrap(self.icmp_code, Color.YELLOW),
                    color_wrap(self.checksum, Color.YELLOW)))
            elif self.protocol == Packet.TCP:
                print('TCP  :: src_port = {} | dest_port = {} | seq = {} | ack = {} |'.format(
                    color_wrap(self.source_port, Color.GREEN),
                    color_wrap(self.dest_port, Color.CYAN),
                    color_wrap(self.seq, Color.YELLOW),
                    color_wrap(self.ack, Color.YELLOW)))
            elif self.protocol == Packet.UDP:
                print('UDP  :: src_port = {} | dest_port = {} | length = {} | checksum = {} |'.format(
                    color_wrap(self.source_port, Color.GREEN),
                    color_wrap(self.dest_port, Color.CYAN),
                    color_wrap(self.length, Color.YELLOW),
                    color_wrap(self.checksum, Color.YELLOW)))
            try:
                d_msg = self.data.decode('utf-8')[:64]
            except UnicodeDecodeError:
                d_msg = self.data[:64]
            print('DATA :: {}'.format(color_wrap(d_msg, Color.BLUE)))

    def parse_eth(self):
        eth_head = self.raw[:self.eth_len]
        self.eth = unpack('!6s6sH', eth_head)
        self.eprot = socket.ntohs(self.eth[2])
        self.destination_mac = mac_addr(self.raw[:6])
        self.source_mac = mac_addr(self.raw[6:12])

    def parse_ip(self):
        ip_head = self.raw[self.eth_len:20+self.eth_len]
        iph = unpack('!BBHHHBBH4s4s', ip_head)
        self.version = iph[0] >> 4
        ihl = iph[0] & 0xF
        self.iph_len = ihl * 4
        self.ttl = iph[5]
        self.protocol = iph[6]
        self.src_addr = socket.inet_ntoa(iph[8])
        self.dest_addr = socket.inet_ntoa(iph[9])

    def parse_tcp(self):
        t = self.iph_len + self.eth_len
        tcp_head = self.raw[t:t+20]
        tcph = unpack('!HHLLBBHHH', tcp_head)
        self.source_port = tcph[0]
        self.dest_port = tcph[1]
        self.seq = tcph[2]
        self.ack = tcph[3]
        self.doff_res = tcph[4]
        self.tcph_len = self.doff_res >> 4
        h_size = self.eth_len + self.iph_len + (self.tcph_len * 4)
        self.data = self.raw[h_size:]

    def parse_udp(self):
        u = self.iph_len + self.eth_len
        udp_head = self.raw[u:u+8]
        udph = unpack('!HHHH', udp_head)
        self.source_port = udph[0]
        self.dest_port = udph[1]
        self.length = udph[2]
        self.checksum = udph[3]
        h_size = self.eth_len + self.iph_len + self.udph_len
        self.data = self.raw[h_size:]

    def parse_icmp(self):
        i = self.eth_len + self.iph_len
        icmp_head = self.raw[i:i+4]
        self.icmph = unpack('!BBH', icmp_head)
        self.src_port = None
        self.dest_port = None
        self.icmp_type = self.icmph[0]
        self.icmp_code = self.icmph[1]
        self.checksum = self.icmph[2]
        h_size = self.eth_len + self.iph_len + self.icmph_len
        self.data = self.raw[h_size:]

    @property
    def ip_packet(self):
        if self.eprot == Packet.IP:
            return True
        return False

class Sniffer:

    def __init__(self, args):
        self.start = time.time()
        self.args = args
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        except socket.error as e:
            cprint('[!] Unable to open socket: {}'.format(e), Color.ERR)
            sys.exit(1)
        self.filtered = 0
        self.parsed = 0

    @property
    def filter_list(self):
        if self.args.filter is None:
            return [Packet.TCP, Packet.ICMP, Packet.UDP]
        retval = []
        if 'tcp' in self.args.filter:
            retval.append(Packet.TCP)
        if 'udp' in self.args.filter:
            retval.append(Packet.UDP)
        if 'icmp' in self.args.filter:
            retval.append(Packet.ICMP)
        return retval

    def run(self):
        self.listen()
        cprint('[*] Packets parsed:   {}'.format(self.parsed), Color.MSG)
        cprint('[*] Packets filtered: {}'.format(self.filtered), Color.MSG)
        cprint('[*] Run time:         {}s'.format(time.time() - self.start), Color.MSG)

    def listen(self):
        with InterruptHandler() as h:
            while True:
                if h.interrupted:
                    cprint('\n[!] Keyboard Interrupt Detected', Color.ERR)
                    return
                try:
                    packet = Packet(self.sock.recvfrom(65565)[0])
                    if packet.protocol in self.filter_list:
                        self.parsed += 1
                        if self.args.src_port is not None:
                            if packet.source_port != self.args.src_port:
                                self.filtered += 1
                                continue
                        if self.args.dest_port is not None:
                            if packet.dest_port != self.args.dest_port:
                                self.filtered += 1
                                continue
                        else:
                            packet.info()
                    else:
                        self.filtered += 1
                except InterruptedError:
                    continue

if __name__ == "__main__":
    this.args = cli()
    app = Sniffer(args)
    app.run()
