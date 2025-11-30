# 数据报捕获模块
import threading
from scapy.all import sniff, get_if_list
from scapy.config import conf
from src.utils.helpers import get_interface_info

class PacketSniffer:
    """数据包嗅探器"""
    def __init__(self, packet_parser, ip_reassembler):
        self.packet_parser = packet_parser
        self.ip_rip_reassemblere = ip_reassembler
        self.is_sniffing = False
        self.sniff_thread = None
        self.captured_packets = []
        self.packet_count = 0
        self.stats = {
            'total_packets': 0,
            'protocols': {},
            'start_time': None
        }

    def get_available_interfaces(self):
        """获取可用网络接口"""
        interfaces = []
        scapy_interfaces = get_if_list()

        for itf in scapy_interfaces:
            info = get_interface_info(itf)
            if info:
                interfaces.append(info)

        return interfaces

    def start_sniffing(self, interface, packer_handler=None, filter_str=""):
        """
        开始捕获数据包

        args:
        interface: 要监听的网络接口名称（如 "eth0", "wlan0" 等）
        packer_handler: 数据包处理回调函数
        filter_str: BPF过滤表达式, 用于筛选特定类型的数据包
        """
        if self.is_sniffing:
            return False
        
        self.is_sniffing = True
        self.packet_count = 0
        self.captured_packets = []
        self.stats = {
            'total_packets': 0,
            'protocols': {},
            'start_time': None
        }
        self.packet_handler = packer_handler

        def sniff_callback(packet):
            """数据包回调函数"""
            if not self.is_sniffing:
                return
            
            self._process_packet(packet)

        # 在独立线程中嗅探
        self.sniff_thread = threading.Thread(
            target=self._sniff_worker,
            args=(interface, sniff_callback, filter_str)
        )
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

        return True

    def _sniff_worker(self, interface, callback, filter_str=""):
        """
        在后台线程中持续监听指定网络接口的数据流量
        
        args:
        interface: 要监听的网络接口名称（如 "eth0", "wlan0" 等）
        callback: 回调函数，对每个捕获的数据包进行处理
        filter_str: BPF过滤表达式, 用于筛选特定类型的数据包
        """
        try:
            sniff(
                iface=interface,
                prn=callback,
                filter=filter_str,
                store=False
            )
        
        except Exception as e:
            print(f"嗅探过程中出错: {e}")

    def _process_packet(self, packet):
        """处理捕获的数据包"""
        self.packet_count += 1
        self.stats['total_packets'] = self.packet_count

        # 解析数据包
        parsed_packet = self.packet_parser.parse_packet(packet, self.packet_count)

        # 更新统计信息
        protocol = parsed_packet.get('protocol', 'Unknown')
        self.stats['protocols'][protocol] = self.stats['protocols'].get(protocol, 0) + 1

        # 保存数据包
        self.captured_packets.append(parsed_packet)

        if self.packet_handler:
            self.packet_handler(parsed_packet, self.stats)

    def stop_sniffing(self):
        """停止嗅探"""
        self.is_sniffing = False
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=2)
            if self.sniff_thread.is_alive():
                print("Warning: 嗅探线程未能及时停止")

    def clear_packets(self):
        """清空捕获的数据包"""
        self.captured_packets.clear()
        self.packet_count = 0
        self.stats = {
            'total_packets': 0,
            'protocols': {},
            'start_time': None
        }

    def get_packet(self, index):
        """获取指定索引的数据包"""
        if index >=0 and index < len(self.captured_packets):
            return self.captured_packets[index]
        return None

    def get_stats(self):
        """获取统计信息"""
        return self.stats.copy()