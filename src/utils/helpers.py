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