# 辅助函数
import psutil
import socket

def get_interface_info(interface_name):
    """获取网络接口详细信息"""
    try:
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()

        if interface_name not in net_if_addrs:
            return None
        
        ip_address = "无IP地址"
        # 找到第一个IPv4地址
        for addr in net_if_addrs[interface_name]:
            if addr.family == socket.AF_INET:
                ip_address = addr.address
                break

        #  获取接口状态
        is_up = False
        if interface_name in net_if_stats:
            is_up = net_if_stats[interface_name].isup
        
        return {
            'name': interface_name,
            'ip': ip_address,
            'status': 'UP' if is_up else 'DOWN',
            'is_up': is_up
        }

    except Exception as e:
        print(f"获取接口信息失败 {interface_name}: {e}")
        return None
    
def format_mac_address(mac):
    """格式化显示MAC地址"""
    if not mac:
        raise ValueError("MAC地址不能为空")
    
    mac_clean = str(mac).replace(":", "").replace("-", "").replace(".", "").replace(" ", "")
    if len(mac_clean) != 12:
        raise ValueError(f"MAC地址长度必须为12个字符, 当前为{len(mac)}")
    if not all(c in "0123456789ABCDEFabcdef" for c in mac_clean):
        raise ValueError(f"MAC地址有效的十六进制字符, 当前为{mac}")
    
    return ':'.join(mac[i:i+2] for i in range(0, len(mac), 2))

def format_hex_data(data, bytes_per_line=16):
    """格式化十六进制数据"""
    if not data:
        return ""
    
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i+bytes_per_line]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04x}: {hex_str:<{bytes_per_line*3}}  {ascii_str}")

    return "\n".join(lines)

def get_protocal_name(protocol_number):
    """根据协议号获取协议名称"""
    protocol_map = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        2: "IGMP",
        41: 'IPv6',
        89: "OSPF",
        47: "GRE",
        50: "ESP",
        51: "AH",
        58: "ICMPv6",
    }
    return protocol_map.get(protocol_number, f"Unknown({protocol_number})")

def guess_protocol(self, packet):
    """猜测数据包协议"""
    if hasattr(packet, 'haslayer'):
        if packet.haslayer('IP'):
            return 'IP'
        elif packet.haslayer('TCP'):
            return 'TCP'
        elif packet.haslayer('UDP'):
            return 'UDP'
        elif packet.haslayer('ICMP'):
            return 'ICMP'
        elif packet.haslayer('ARP'):
            return 'ARP'
    return 'Unknown'

def get_dns_opcode(opcode):
    """获取DNS操作码描述"""
    opcodes = {
        0: 'QUERY',
        1: 'IQUERY',
        2: 'STATUS',
        4: 'NOTIFY',
        5: 'UPDATE'
    }
    return opcodes.get(opcode, f'Unknown({opcode})')

def get_dns_rcode(rcode):
    """获取DNS返回码描述"""
    rcodes = {
        0: 'No error',
        1: 'Format error',
        2: 'Server failure',
        3: 'Name Error',
        4: 'Not Implemented',
        5: 'Refused'
    }
    return rcodes.get(rcode, f'Unknown({rcode})')

def get_dns_type(qtype):
    """获取DNS类型描述"""
    types = {
        1: 'A',
        2: 'NS',
        5: 'CNAME',
        6: 'SOA',
        12: 'PTR',
        15: 'MX',
        16: 'TXT',
        28: 'AAAA',
        33: 'SRV'
    }
    return types.get(qtype, f'Type{qtype}')

def get_dns_class(qclass):
    """获取DNS类别描述"""
    classes = {
        1: 'IN',  # Internet
        3: 'CH',  # Chaos
        4: 'HS'   # Hesiod
    }
    return classes.get(qclass, f'Class{qclass}')

def format_dns_rdata(rr):
    """格式化DNS资源记录数据"""
    if hasattr(rr, 'rdata'):
        if rr.type == 1:  # A记录
            return rr.rdata
        elif rr.type == 5:  # CNAME记录
            return rr.rname.decode('utf-8', errors='ignore') if isinstance(rr.rname, bytes) else str(rr.rname)
        elif rr.type == 12:  # PTR记录
            return rr.rdata.decode('utf-8', errors='ignore') if isinstance(rr.rdata, bytes) else str(rr.rdata)
        elif rr.type == 28:  # AAAA记录
            return rr.rdata
        elif rr.type == 15:  # MX记录
            return f"{rr.preference} {rr.exchange.decode('utf-8', errors='ignore') if isinstance(rr.exchange, bytes) else rr.exchange}"
        elif rr.type == 16:  # TXT记录
            if isinstance(rr.rdata, bytes):
                return rr.rdata.decode('utf-8', errors='ignore')
            elif isinstance(rr.rdata, str):
                return rr.rdata
            elif hasattr(rr, 'txt_string'):
                return rr.txt_string
    return str(rr.rdata) if hasattr(rr, 'rdata') else 'Unknown'