# 协议解析模块
from scapy.all import Ether, IP, ARP, ICMP, TCP, UDP, DNS, DNSQR, DNSRR, Raw
from datetime import datetime
import json
from utils.helpers import get_dns_opcode, get_dns_rcode, get_dns_type, get_dns_class, format_dns_rdata

class ProtocolParser:
    """协议解析模块"""
    def __init__(self):
        self.supported_protocols = ['Ethernet', 'IP', 'ARP', 'ICMP', 'TCP', 'UDP', 'DNS']

    def parse_packet(self, packet, packet_number, is_reassembled=False):
        """解析数据包"""
        parsed_data = {
            'number': packet_number,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            'length': len(packet),
            'protocol': 'Unknown',
            'summary': '',
            'layers': {},
            'hexdump': '', # 十六进制转储
            'is_fragment': False,
            'is_reassembled': is_reassembled,
            'fragment_info': None,
            'fragment_id': None,  # 添加分片ID字段
            'fragment_offset': 0,  # 添加分片偏移字段
            'is_last_fragment': False  # 添加是否最后一个分片字段
        }

        # 添加重组标记
        if is_reassembled:
            parsed_data['summary'] = f"[Reassembled] {packet.summary()}"
        else:
            parsed_data['summary'] = packet.summary()

        # 检查是否为IP分片
        if packet.haslayer(IP):
            ip = packet[IP]
            is_fragment = ip.flags.MF or ip.frag > 0
            parsed_data['is_fragment'] = is_fragment
            parsed_data['fragment_id'] = ip.id
            parsed_data['fragment_offset'] = ip.frag
            parsed_data['is_last_fragment'] = not ip.flags.MF and ip.frag > 0
            
            if is_fragment:
                fragment_number = (ip.frag // 8) + 1
                if ip.frag == 0:
                    fragment_info = f"First fragment (ID: {ip.id})"
                elif ip.flags.MF:
                    fragment_info = f"Middle fragment {fragment_number} (ID: {ip.id})"
                else:
                    fragment_info = f"Last fragment {fragment_number} (ID: {ip.id})"
                parsed_data['fragment_info'] = fragment_info

        # 数据链路层 - Ethernet
        if packet.haslayer(Ether):
            parsed_data['layers']['Ethernet'] = self._parse_ethernet(packet[Ether])
            parsed_data['protocol'] = 'Ethernet'

        # 网络层 - IP/ARP/ICMP
        if packet.haslayer(IP):
            parsed_data['layers']['IP'] = self._parse_ip(packet[IP], is_reassembled)
            parsed_data['protocol'] = 'IP'
            
            # 根据IP层信息确定协议名称
            if packet.haslayer(ICMP):
                parsed_data['protocol'] = 'ICMP'
            elif packet.haslayer(TCP):
                parsed_data['protocol'] = 'TCP'
            elif packet.haslayer(UDP):
                parsed_data['protocol'] = 'UDP'

        if packet.haslayer(ARP):
            parsed_data['layers']['ARP'] = self._parse_arp(packet[ARP])
            parsed_data['protocol'] = 'ARP'
            
        if packet.haslayer(ICMP):
            parsed_data['layers']['ICMP'] = self._parse_icmp(packet[ICMP])
            # parsed_data['protocol'] = 'ICMP'

        # 传输层 - TCP/UDP    
        if packet.haslayer(TCP):
            parsed_data['layers']['TCP'] = self._parse_tcp(packet[TCP])
            # parsed_data['protocol'] = 'TCP'
            
        if packet.haslayer(UDP):
            parsed_data['layers']['UDP'] = self._parse_udp(packet[UDP])
            # parsed_data['protocol'] = 'UDP'

        # 解析负载数据
        parsed_data['payload'] = self._parse_payload(packet)

        # 生成摘要信息
        summary_parts = []
        if packet.haslayer(Ether):
            summary_parts.append('Ether')
        if packet.haslayer(IP):
            summary_parts.append('IP')
        if packet.haslayer(ICMP):
            summary_parts.append('ICMP')
        elif packet.haslayer(TCP):
            summary_parts.append('TCP')
        elif packet.haslayer(UDP):
            summary_parts.append('UDP')
        if packet.haslayer(Raw):
            summary_parts.append('Raw')
        
        base_summary = ' / '.join(summary_parts)

        # 如果是重组包，在摘要前添加标记
        if is_reassembled:
            parsed_data['summary'] = f"[Reassembled] {base_summary}"
        elif parsed_data['is_fragment']:
            # 分片包显示分片信息
            ip = packet[IP]
            if ip.frag == 0 and packet.haslayer(ICMP):
                # 第一个分片包含ICMP头
                parsed_data['summary'] = f"{base_summary} [Fragment {parsed_data['fragment_info']}]"
            else:
                # 后续分片不包含上层协议头
                parsed_data['summary'] = f"Ether / IP [Fragment {parsed_data['fragment_info']}]"
        else:        
            parsed_data['summary'] = base_summary
            
        # 生成十六进制转储
        parsed_data['hexdump'] = self._generate_hexdump(packet)
        return parsed_data
    
    def _try_parse_dns_from_payload(self, packet):
        """尝试从负载解析DNS数据"""
        try:
            # 获取原始负载
            if packet.haslayer(Raw):
                raw_data = packet[Raw].load
                
                # 对于TCP DNS，可能需要跳过长度字段
                if packet.haslayer(TCP):
                    # DNS over TCP有2字节的长度字段
                    if len(raw_data) > 2:
                        raw_data = raw_data[2:]  # 跳过长度字段

                # 尝试用Scapy解析
                if raw_data:
                    dns = DNS(raw_data)
                    if dns:
                        return self._parse_dns(dns)
        except Exception as e:
            print(f"DNS解析失败: {e}")
        
        # 如果解析失败，返回基本信息
        return None

    def _parse_dns(self, dns):
        """解析DNS数据包"""
        dns_info = {
            'id': dns.id,
            'qr': 'Response' if dns.qr else 'Query',
            'opcode': get_dns_opcode(dns.opcode),
            'aa': dns.aa,
            'tc': dns.tc,
            'rd': dns.rd,
            'ra': dns.ra,
            'z': dns.z,
            'ad': dns.ad,
            'cd': dns.cd,
            'rcode': get_dns_rcode(dns.rcode),
            'qdcount': dns.qdcount,
            'ancount': dns.ancount,
            'nscount': dns.nscount,
            'arcount': dns.arcount,
        }
        
        # 查询部分
        if dns.qd and dns.qdcount > 0:
            queries = []
            for i in range(min(dns.qdcount, len(dns.qd))):
                q = dns.qd[i]
                query_info = {
                    'name': q.qname.decode('utf-8', errors='ignore') if isinstance(q.qname, bytes) else str(q.qname),
                    'type': get_dns_type(q.qtype),
                    'class': get_dns_class(q.qclass)
                }
                queries.append(query_info)
            dns_info['queries'] = queries
        
        # 回答部分
        if dns.an and dns.ancount > 0:
            answers = []
            for i in range(min(dns.ancount, len(dns.an))):
                a = dns.an[i]
                answer_info = {
                    'name': a.rrname.decode('utf-8', errors='ignore') if isinstance(a.rrname, bytes) else str(a.rrname),
                    'type': get_dns_type(a.type),
                    'class': get_dns_class(a.rclass),
                    'ttl': a.ttl,
                    'data': format_dns_rdata(a)
                }
                answers.append(answer_info)
            dns_info['answers'] = answers

        # 权威部分
        if dns.ns and dns.nscount > 0:
            authorities = []
            for i in range(min(dns.nscount, len(dns.ns))):
                ns = dns.ns[i]
                ns_info = {
                    'name': ns.rrname.decode('utf-8', errors='ignore') if isinstance(ns.rrname, bytes) else str(ns.rrname),
                    'type': get_dns_type(ns.type),
                    'class': get_dns_class(ns.rclass),
                    'ttl': ns.ttl,
                    'data': format_dns_rdata(ns)
                }
                authorities.append(ns_info)
            dns_info['authorities'] = authorities

        # 附加部分
        if dns.ar and dns.arcount > 0:
            additionals = []
            for i in range(min(dns.arcount, len(dns.ar))):
                ar = dns.ar[i]
                ar_info = {
                    'name': ar.rrname.decode('utf-8', errors='ignore') if isinstance(ar.rrname, bytes) else str(ar.rrname),
                    'type': get_dns_type(ar.type),
                    'class': get_dns_class(ar.rclass),
                    'ttl': ar.ttl,
                    'data': format_dns_rdata(ar)
                }
                additionals.append(ar_info)
            dns_info['additionals'] = additionals
        
        # 生成描述
        description = f"DNS {dns_info['qr']}"
        if 'queries' in dns_info and dns_info['queries']:
            query_names = [q['name'] for q in dns_info['queries']]
            description += f" for {', '.join(query_names)}"
        
        dns_info['description'] = description
        return dns_info

    def _parse_ethernet(self, ether):
        """解析以太网帧"""
        return {
            'source_mac': ether.src,
            'destination_mac': ether.dst,
            'type': ether.type, # 指明上层（网络层）使用的协议
            'description': f"{ether.src} -> {ether.dst}"
        }

    def _parse_ip(self, ip, is_reassembled=False):
        """解析IP数据包"""
        description = f"{ip.src} -> {ip.dst} Proto: {ip.proto}"
        
        # 检查是否为分片
        is_fragment = ip.flags.MF or ip.frag > 0
        
        if is_fragment and not is_reassembled:
            # 计算分片序号
            fragment_number = (ip.frag // 8) + 1  # ip.frag是8字节为单位，+1从1开始计数
            
            # 判断分片状态
            if ip.frag == 0:
                fragment_info = f"First fragment (ID: {ip.id})"
                description = f"{ip.src} > {ip.dst} IP Fragment {fragment_info}"
            elif ip.flags.MF:
                fragment_info = f"Middle fragment {fragment_number} (ID: {ip.id})"
                description = f"{ip.src} > {ip.dst} IP Fragment {fragment_info}"
            else:
                fragment_info = f"Last fragment {fragment_number} (ID: {ip.id})"
                description = f"{ip.src} > {ip.dst} IP Fragment {fragment_info}"
        
        elif not is_fragment:
            # 不是分片包
            fragment_info = "Not a fragment"
            if ip.haslayer(ICMP):
                icmp = ip[ICMP]
                icmp_type = icmp.type
                type_map = {0: 'echo-reply', 8: 'echo-request'}
                icmp_desc = type_map.get(icmp_type, f'icmp-type-{icmp_type}')
                description = f"{ip.src} > {ip.dst} {icmp_desc} 0"
            else:
                description = f"{ip.src} -> {ip.dst} Proto: {ip.proto}"
        else:
            # 重组包
            fragment_info = "Reassembled"
            if ip.haslayer(ICMP):
                icmp = ip[ICMP]
                icmp_type = icmp.type
                type_map = {0: 'echo-reply', 8: 'echo-request'}
                icmp_desc = type_map.get(icmp_type, f'icmp-type-{icmp_type}')
                description = f"{ip.src} > {ip.dst} {icmp_desc} 0"
            else:
                description = f"{ip.src} -> {ip.dst} Proto: {ip.proto}"

        # 如果是重组包，添加标记
        if is_reassembled:
            description = f"[Reassembled] {description}"

        result = {
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
            'protocol_name': self._get_proto_name(ip.proto),
            'header_checksum': f"0x{ip.chksum:04x}" if ip.chksum is not None else "0x0000",
            'source_ip': ip.src,
            'destination_ip': ip.dst,
            'is_fragment': is_fragment,
            'fragment_number': (ip.frag // 8) + 1 if is_fragment else 0,
            'fragment_info': fragment_info,
            'is_reassembled': is_reassembled,
            'description': description
        }
        
        return result
    
    def _get_proto_name(self, proto_num):
        """将协议号转换为协议名称"""
        proto_map = {
            1: 'ICMP',
            2: 'IGMP',
            6: 'TCP',
            17: 'UDP',
            58: 'ICMPv6'
        }
        return proto_map.get(proto_num, f'Proto-{proto_num}')

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
    
    # def _parse_icmp(self, icmp):
    #     """解析ICMP数据包"""
    #     type_map = {
    #         0: 'Echo Reply',
    #         3: 'Destination Unreachable',
    #         8: 'Echo Request',
    #         11: 'Time Exceeded'
    #     }
    #     return{
    #         'type': type_map.get(icmp.type, f'Unknown({icmp.type})'),
    #         'code': icmp.code,
    #         'checksum': f"0x{icmp.chksum:04x}",
    #         'description': type_map.get(icmp.type, f'ICMP Type {icmp.type}')
    #     }

    def _parse_icmp(self, icmp):
        """解析ICMP数据包"""
        type_map = {
            0: 'Echo Reply',
            3: 'Destination Unreachable',
            8: 'Echo Request',
            11: 'Time Exceeded'
        }
        
        icmp_type = type_map.get(icmp.type, f'Unknown({icmp.type})')
        description = f"{icmp_type}"
        
        # 如果是echo请求或回复，显示更多信息
        if icmp.type in [0, 8] and hasattr(icmp, 'id') and hasattr(icmp, 'seq'):
            description = f"{icmp_type} id=0x{icmp.id:04x} seq={icmp.seq}"
        
        return{
            'type': icmp_type,
            'type_code': icmp.type,
            'code': icmp.code,
            'checksum': f"0x{icmp.chksum:04x}",
            'id': getattr(icmp, 'id', None),
            'sequence': getattr(icmp, 'seq', None),
            'description': description
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