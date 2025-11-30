# 协议解析模块
from scapy.all import Ether, IP, ARP, ICMP, TCP, UDP
from datetime import datetime
import json

class ProtocolParser:
    """协议解析模块"""
    def __init__(self):
        self.supported_protocols = ['Ethernet', 'IP', 'ARP', 'ICMP', 'TCP', 'UDP']

    def parse_packet(self, packet, packet_number):
        """解析数据包"""
        parsed_data = {
            'number': packet_number,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            'length': len(packet),
            'protocol': 'Unknown',
            'summary': '',
            'layers': {},
            'hexdump': '' # 十六进制转储
        }

        parsed_data['summary'] = packet.summary()

        # 数据链路层 - Ethernet
        if packet.haslayer(Ether):
            parsed_data['layers']['Ethernet'] = self._parse_ethernet(packet[Ether])
            parsed_data['protocol'] = 'Ethernet'

        # 网络层 - IP/ARP/ICMP
        if packet.haslayer(IP):
            parsed_data['layers']['IP'] = self._parse_ip(packet[IP])
            parsed_data['protocol'] = 'IP'
            
        if packet.haslayer(ARP):
            parsed_data['layers']['ARP'] = self._parse_arp(packet[ARP])
            parsed_data['protocol'] = 'ARP'
            
        if packet.haslayer(ICMP):
            parsed_data['layers']['ICMP'] = self._parse_icmp(packet[ICMP])
            parsed_data['protocol'] = 'ICMP'

        # 传输层 - TCP/UDP    
        if packet.haslayer(TCP):
            parsed_data['layers']['TCP'] = self._parse_tcp(packet[TCP])
            parsed_data['protocol'] = 'TCP'
            
        if packet.haslayer(UDP):
            parsed_data['layers']['UDP'] = self._parse_udp(packet[UDP])
            parsed_data['protocol'] = 'UDP'

        # 解析负载数据
        parsed_data['payload'] = self._parse_payload(packet)

        # 生成十六进制转储
        parsed_data['hexdump'] = self._generate_hexdump(packet)

    
    def _parse_ethernet(self, ether):
        """解析以太网帧"""
        return {
            'source_mac': ether.src,
            'destination_mac': ether.dst,
            'type': ether.type, # 指明上层（网络层）使用的协议
            'description': f"{ether.src} -> {ether.dst}"
        }

    def _parse_ip(self, ip):
        """解析IP数据包"""
        return{
            'version': ip.version,
            'header_length': ip.ihl * 4,
            'tos': ip.tos,
            'total_length': ip.len,
            'identification': ip.id,
            'flags': {
                'MF': ip.flags.MF,
                'DF': ip.flags.DF,
                'evil': ip.flags.evil
            },
            'fragment_offset': ip.frag,
            'ttl': ip.ttl,
            'protocol': ip.proto,
            'header_checksum': f"0x{ip.chksum:04x}",
            'source_ip': ip.src,
            'destination_ip': ip.dst,
            'description': f"{ip.src} -> {ip.dst} Proto: {ip.proto}"
        }

    def _parse_arp(self, arp):
        """解析ARP数据包"""
        op_map = {1: 'ARP Request', 2: 'ARP Reply'}
        return {
            'hardware_type': arp.hwtype,
            'protocol_type': arp.ptype,
            'hardware_size': arp.hwlen,
            'protocol_size': arp.plen,
            'opcode': op_map.get(arp.op, f'Unknown ({arp.op})'),
            'sender_mac': arp.hwsrc,
            'sender_ip': arp.psrc,
            'target_mac': arp.hwdst,
            'target_ip': arp.pdst,
            'description': f"{arp.psrc} -> {arp.pdst} ({op_map.get(arp.op, 'Unknown')})"
        }
    
    def _parse_icmp(self, icmp):
        """解析ICMP数据包"""
        type_map = {
            0: 'Echo Reply',
            3: 'Destination Unreachable',
            8: 'Echo Request',
            11: 'Time Exceeded'
        }
        return{
            'type': type_map.get(icmp.type, f'Unknown({icmp.type})'),
            'code': icmp.code,
            'checksum': f"0x{icmp.chksum:04x}",
            'description': type_map.get(icmp.type, f'ICMP Type {icmp.type}')
        }

    def _parse_tcp(self, tcp):
        """解析TCP数据包"""
        flags = []
        if tcp.flags.F: flags.append('FIN')
        if tcp.flags.S: flags.append('SYN')
        if tcp.flags.R: flags.append('RST')
        if tcp.flags.P: flags.append('PSH')
        if tcp.flags.A: flags.append('ACK')
        if tcp.flags.U: flags.append('URG')
        if tcp.flags.E: flags.append('ECE')
        if tcp.flags.C: flags.append('CWR')

        return{
            'source_port': tcp.sport,
            'destination_port': tcp.dport,
            'sequence_number': tcp.seq,
            'acknowledgment_number': tcp.ack,
            'header_length': tcp.dataofs * 4,
            'flags': ','.join(flags),
            'window_size': tcp.window,
            'checksum': f"0x{tcp.chksum:04x}",
            'urgent_pointer': tcp.urgptr,
            'description': f"{tcp.sport} -> {tcp.dport} [{', '.join(flags)}]"
        }

    def _parse_udp(self, udp):
        """解析UDP数据包"""
        return {
            'source_port': udp.sport,
            'destination_port': udp.dport,
            'length': udp.len,
            'checksum': f"0x{udp.chksum:04x}",
            'description': f"{udp.sport} -> {udp.dport}"
        }

    def _parse_payload(self, packet):
        """解析负载数据"""
        payload = bytes(packet.payload) if packet.payload else b''

        # 尝试解码为文本
        try:
            text = payload.decode('utf-8', errors='ignore')
            if any(c.isprintable() or c in '\r\n\t' for c in text[:100]):
                return {
                    'size': len(payload),
                    'hex': payload.hex()[:200] + '...' if len(payload) > 100 else payload.hex(),
                    'text': text[:500] + '...' if len(text) > 500 else text
                }

        except:
            pass

        return {
            'size': len(payload),
            'hex': payload.hex()[:200] + '...' if len(payload) > 100 else payload.hex(),
            'text': '[Binary Data]'  # 标记为二进制数据
        }
    
    def _generate_hexdump(self, packet):
        """生成十六进制转储"""
        raw_data = bytes(packet)
        hexdump = ""

        for i in range(0, len(raw_data), 16):
            # 十六进制部分
            hex_part = " ".join(f"{b:02x}" for b in raw_data[i:i+8])
            hex_part += "  " + " ".join(f"{b:02x}" for b in raw_data[i+8:i+16])
            
            # ASCII部分
            ascii_part = ""
            for b in raw_data[i:i+16]:
                if 32 <= b <= 126:  # 可打印字符
                    ascii_part += chr(b)
                else:
                    ascii_part += "."  # 不可打印字符显示为.
            
            hexdump += f"{i:04x}  {hex_part:<48}  {ascii_part}\n"
            
        return hexdump