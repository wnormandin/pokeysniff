#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import sys
import time
import signal
from struct import unpack

import argparse
this = sys.modules[__name__]

VERSION = '0.1a'
RELEASE = 'Development'

if sys.version_info[0] < 3:
    # Python 3 required for command line execution
    raise AssertionError("Must use Python 3")

def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument('--filter', nargs='*', help='filter packets by type',
                        choices=['tcp','udp','icmp'])
    parser.add_argument('--src-port', nargs='*', help='filter packets by source port')
    parser.add_argument('--src-ip', nargs='*', help='filter packets by source IP')
    parser.add_argument('--dest-port', nargs='*', help='filter packets by destination port')
    parser.add_argument('--dest-ip', nargs='*', help='filter packets by destination IP')
    parser.add_argument('--nocolor', action='store_true', help='Skip colors in output')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--no-data', action='store_true', help='Skip printing raw data')
    return parser.parse_args()

def mac_addr(addr):
    # Takes a list of mac addr components
    return ':'.join(['{:02x}'.format(a) for a in addr])

def cprint(val, col=None, verbose=False):
    if not args.verbose and verbose:
        return
    if col==None:
        msg = val
    else:
        msg = color_wrap(val, col)
    # Skipping print buffering
    msg += '\n'
    sys.stdout.write(msg)

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

    # Unpack arg[0] for raw packet conversion
    U_ETH = '!6s6sH'
    U_IP = '!BBHHHBBH4s4s'
    U_TCP = '!HHLLBBHHH'
    U_UDP = '!HHHH'
    U_ICMP = '!BBH'

    def __init__(self, raw):
        self.protocol = 0
        self.raw = raw
        self.parse_eth()
        self._info_cache = False
        self.src_port = 0
        self.dest_port = 0
        self.src_addr = '0'
        self.dest_addr = '0'
        if self.ip_packet:
            self.parse_ip()
            self.parse_body()

    def info(self):
        print('\nETH  :: eprotocol = {} | source MAC = {} | destination MAC = {} |'.format(
            color_wrap(self.eprot, Color.YELLOW),
            color_wrap(self.source_mac, Color.GREEN),
            color_wrap(self.destination_mac, Color.CYAN)))
        if not self.ip_packet:
            cprint('[!] Not an IP packet', Color.MSG)
            return
        else:
            print('IP   :: version = {} | ttl = {} | protocol = {} | source IP = {} | destination IP = {} |'.format(
                color_wrap(self.version, Color.YELLOW),
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
                    color_wrap(self.icmp_type, Color.YELLOW),
                    color_wrap(self.icmp_code, Color.YELLOW),
                    color_wrap(self.checksum, Color.YELLOW)))
            elif self.protocol == Packet.TCP:
                print('TCP  :: src_port = {} | dest_port = {} | seq = {} | ack = {} |'.format(
                    color_wrap(self.src_port, Color.GREEN),
                    color_wrap(self.dest_port, Color.CYAN),
                    color_wrap(self.seq, Color.YELLOW),
                    color_wrap(self.ack, Color.YELLOW)))
            elif self.protocol == Packet.UDP:
                print('UDP  :: src_port = {} | dest_port = {} | length = {} | checksum = {} |'.format(
                    color_wrap(self.src_port, Color.GREEN),
                    color_wrap(self.dest_port, Color.CYAN),
                    color_wrap(self.length, Color.YELLOW),
                    color_wrap(self.checksum, Color.YELLOW)))

            try:
                d_msg = self.data.decode('utf-8')[:64]
            except UnicodeDecodeError:
                d_msg = self.data[:64]

            if not args.no_data:
                cprint('DATA :: {}'.format(color_wrap(d_msg, Color.BLUE)), None, True)

    def parse_eth(self):
        eth_head = self.raw[:self.eth_len]
        self.eth = unpack(Packet.U_ETH, eth_head)
        self.eprot = socket.ntohs(self.eth[2])
        self.destination_mac = mac_addr(self.raw[:6])
        self.source_mac = mac_addr(self.raw[6:12])

    def parse_ip(self):
        ip_head = self.raw[self.eth_len:20+self.eth_len]
        iph = unpack(Packet.U_IP, ip_head)
        self.version = iph[0] >> 4
        ihl = iph[0] & 0xF
        self.iph_len = ihl * 4
        self.ttl = iph[5]
        self.protocol = iph[6]
        self.src_addr = socket.inet_ntoa(iph[8])
        self.dest_addr = socket.inet_ntoa(iph[9])

    def parse_body(self):
        self.header = unpack(self.proto_u, self.raw_header)
        if self.protocol == Packet.ICMP:
            self.src_port = self.dest_port = 0
            self.parse_icmp()
        elif self.protocol in [Packet.TCP, Packet.UDP]:
            self.src_port = self.header[0]
            self.dest_port = self.header[1]
            if self.protocol == Packet.TCP:
                self.parse_tcp()
            elif self.protocol == Packet.UDP:
                self.parse_udp()
        self.data = self.raw[self.len_h:]

    @property
    def proto_u(self):
        if self.protocol == Packet.TCP:
            return Packet.U_TCP
        elif self.protocol == Packet.UDP:
            return Packet.U_UDP
        elif self.protocol == Packet.ICMP:
            return Packet.U_ICMP

    @property
    def base_h(self):
        return self.iph_len + self.eth_len

    @property
    def len_h(self):
        if self.protocol == Packet.TCP:
            return self.base_h + (self.tcph_len * 4)
        elif self.protocol == Packet.UDP:
            return self.base_h + self.udph_len
        elif self.protocol == Packet.ICMP:
            return self.base_h + self.icmph_len
        return 0

    @property
    def raw_header(self):
        h = self.base_h
        if self.protocol == Packet.TCP:
            offset = 20
        elif self.protocol == Packet.UDP:
            offset = 8
        elif self.protocol == Packet.ICMP:
            offset = 4
        return self.raw[h:h+offset]

    def parse_tcp(self):
        self.seq = self.header[2]
        self.ack = self.header[3]
        self.doff_res = self.header[4]
        self.tcph_len = self.doff_res >> 4

    def parse_udp(self):
        self.length = self.header[2]
        self.checksum = self.header[3]

    def parse_icmp(self):
        self.icmp_type = self.header[0]
        self.icmp_code = self.header[1]
        self.checksum = self.header[2]

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
        cprint(' -  Packets parsed:   {}'.format(self.parsed), Color.GREEN, True)
        cprint(' -  Packets filtered: {}'.format(self.filtered), Color.GREEN, True)
        cprint(' -  Run time:         {}s'.format(time.time() - self.start), Color.GREEN, True)

    def _filter(self, p):
        if any([
                p.protocol not in self.filter_list,
                self.args.src_port and str(p.src_port) not in self.args.src_port,
                self.args.dest_port and str(p.dest_port) not in self.args.dest_port,
                self.args.src_ip and p.src_addr not in self.args.src_ip,
                self.args.dest_ip and p.dest_ip not in self.args.dest_ip
                ]):
            return False
        return True

    def listen(self):
        cprint('[!] Listening for packets', Color.MSG)
        with InterruptHandler() as h:
            while True:
                if h.interrupted:
                    print('\n')
                    cprint('[!] Keyboard Interrupt Detected', Color.ERR)
                    return
                try:
                    packet = Packet(self.sock.recvfrom(65565)[0])
                    if self._filter(packet):
                        self.parsed += 1
                        packet.info()
                    else:
                        self.filtered += 1
                except InterruptedError:
                    continue

if __name__ == "__main__":
    this.args = cli()
    cprint('[*] PokeySniff v{} ({})'.format(VERSION, RELEASE), Color.MSG)
    cprint(' -  Command line arguments parsed', Color.GREEN, True)
    app = Sniffer(args)
    cprint(' -  Port sniffer spawned', Color.GREEN, True)
    app.run()
    cprint('[!] Completed', Color.MSG)
