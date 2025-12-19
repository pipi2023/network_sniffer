# 数据报捕获模块
import threading
import time
import scapy.all as scapy
from scapy.all import sniff, get_if_list, IP
from scapy.config import conf
from src.utils.helpers import get_interface_info, guess_protocol

class PacketSniffer:
    """数据包嗅探器"""
    def __init__(self, packet_parser=None, ip_reassembler=None):
        self.packet_parser = packet_parser
        self.ip_reassembler = ip_reassembler
        self.is_sniffing = False
        self.sniff_thread = None
        self.captured_packets = []
        self.packet_count = 0
        self.stats = {
            'total_packets': 0,
            'bytes_received': 0,
            'protocols': {},
            'start_time': None
        }

        self.debug_mode = True  # 添加调试开关
        self.packet_handler = None
        # 保存启动参数，便于重新启动
        self.sniff_params = None
        # 导入放在这里，避免循环导入
        self.scapy = None
        self._import_scapy()

    def _import_scapy(self):
        """动态导入Scapy, 每次重新导入"""
        try:
            import importlib
            # 重新导入scapy模块
            importlib.reload(scapy)
            self.scapy = scapy
            print("Scapy模块重新加载")
        except Exception as e:
            print(f"重新导入Scapy失败: {e}")
            self.scapy = scapy  # 使用原来的

    def get_available_interfaces(self):
        """获取可用网络接口"""
        interfaces = []
        scapy_interfaces = get_if_list()

        for itf in scapy_interfaces:
            info = get_interface_info(itf)
            if info:
                interfaces.append(info)

        return interfaces

    def start_sniffing(self, interface, packet_handler=None, filter_str=""):
        """
        开始捕获数据包

        args:
        interface: 要监听的网络接口名称（如 "eth0", "wlan0" 等）
        packer_handler: 数据包处理回调函数
        filter_str: BPF过滤表达式, 用于筛选特定类型的数据包
        """
        self.stop_sniffing()
        time.sleep(0.5)

        self._reset_all_state()
        # 重新导入Scapy，确保每次都是新的实例
        self._import_scapy()

        if self.is_sniffing:
            return False

        # 保存参数（用于重启）
        self.sniff_params = {
            'interface': interface,
            'packet_handler': packet_handler,
            'filter_str': filter_str
        }
        
        self.packet_handler = packet_handler
        self.is_sniffing = True
        
        # 在独立线程中嗅探
        self.sniff_thread = threading.Thread(
            target=self._sniff_worker,
            args=(interface, self._sniff_callback_wrapper, filter_str),
            name=f"Sniffer-{interface}-{int(time.time())}"
        )
        self.sniff_thread.daemon = True
        self.sniff_thread.start()
        
        # 等待线程启动
        time.sleep(0.2)
        
        return True

    def _sniff_callback_wrapper(self, packet):
        """包装回调函数，确保线程安全"""
        if not self.is_sniffing:
            return False
        
        try:
            self._process_packet(packet)
        except Exception as e:
            if self.debug_mode:
                print(f"DEBUG: 处理数据包时出错: {e}")
                import traceback
                traceback.print_exc()
        
        return True

    def _sniff_worker(self, interface, callback, filter_str=""):
        """
        使用 AsyncSniffer 进行嗅探（推荐）
        """
        try:
            from scapy.all import AsyncSniffer, get_if_list
            
            # 检查接口
            available_interfaces = get_if_list()
            if interface not in available_interfaces:
                print(f"接口 {interface} 不存在，使用默认接口")
                if available_interfaces:
                    interface = available_interfaces[0]
                else:
                    print("错误: 没有可用的网络接口")
                    return
            
            # 处理过滤条件
            actual_filter = filter_str.strip() if filter_str and filter_str.strip() else None
            
            print(f"开始嗅探 - 接口: {interface}, 过滤器: '{actual_filter}'")
            
            # 创建异步嗅探器
            self.async_sniffer = AsyncSniffer(
                iface=interface,
                filter=actual_filter,
                prn=callback,
                store=False,
                promisc=True
            )
            
            # 启动嗅探
            self.async_sniffer.start()
            print("异步嗅探器已启动")
            
            # 等待停止信号
            while self.is_sniffing:
                time.sleep(0.5)  # 每0.5秒检查一次
                
            # 停止嗅探器
            if hasattr(self, 'async_sniffer') and self.async_sniffer:
                print("正在停止异步嗅探器...")
                self.async_sniffer.stop()
                self.async_sniffer = None
                
            print(f"嗅探线程正常结束")
            
        except Exception as e:
            print(f"嗅探线程出错: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.is_sniffing = False
            print(f"嗅探线程清理完成")

    def stop_sniffing(self):
        """停止嗅探"""
        if not self.is_sniffing:
            return
        
        print("正在停止嗅探...")
        self.is_sniffing = False
        
        # 停止异步嗅探器
        if hasattr(self, 'async_sniffer') and self.async_sniffer:
            try:
                self.async_sniffer.stop()
                self.async_sniffer = None
                print("异步嗅探器已停止")
            except Exception as e:
                print(f"停止异步嗅探器时出错: {e}")
        
        # 等待线程结束
        if hasattr(self, 'sniff_thread') and self.sniff_thread:
            print(f"等待嗅探线程停止: {self.sniff_thread.name}")
            self.sniff_thread.join(timeout=3.0)
            self.sniff_thread = None
        
        print("嗅探已停止")
    
    def _force_cleanup(self):
        """强制清理 Scapy 资源"""
        try:
            import scapy.all as scapy_mod
            
            # 关闭所有可能的 socket
            if hasattr(scapy_mod.conf, 'L2socket'):
                try:
                    scapy_mod.conf.L2socket.close()
                except:
                    pass
            
            if hasattr(scapy_mod.conf, 'L3socket'):
                try:
                    scapy_mod.conf.L3socket.close()
                except:
                    pass
            
            # 重置所有配置
            scapy_mod.conf.iface = None
            scapy_mod.conf.sniff_promisc = True
            scapy_mod.conf.promisc = True
            scapy_mod.conf.sniff_socket = None
            scapy_mod.conf.L2listen = None
            
            # 清理缓存
            if hasattr(scapy_mod, '__dict__'):
                # 清理可能残留的全局变量
                for key in list(scapy_mod.__dict__.keys()):
                    if key.startswith('_') or key in ['conf', 'all']:
                        continue
                    try:
                        delattr(scapy_mod, key)
                    except:
                        pass
            
            print("强制清理 Scapy 资源完成")
            
        except Exception as e:
            print(f"强制清理时出错: {e}")
    
    def _cleanup_scapy(self):
        """清理Scapy状态，准备重新启动"""
        try:
            # 清理可能的全局状态
            import scapy.all as scapy_mod
            
            # 关闭socket
            if hasattr(scapy_mod.conf, 'L2socket'):
                try:
                    scapy_mod.conf.L2socket.close()
                except:
                    pass
            
            # 重置配置
            scapy_mod.conf.iface = None
            scapy_mod.conf.sniff_promisc = True
            scapy_mod.conf.promisc = True
            
            # 清理可能的缓存
            if hasattr(scapy_mod, 'cache'):
                scapy_mod.cache.clear()
                
        except Exception as e:
            print(f"清理Scapy状态时出错: {e}")
    
    def restart_sniffing(self):
        """重新启动嗅探"""
        if self.sniff_params:
            return self.start_sniffing(
                interface=self.sniff_params['interface'],
                packet_handler=self.sniff_params['packet_handler'],
                filter_str=self.sniff_params['filter_str']
            )
        return False

    def _process_packet(self, packet):
        """处理捕获的数据包"""
        if not self.is_sniffing:
            return

        if self.debug_mode:
            protocol = "Unknown"
            if hasattr(packet, 'haslayer'):
                if packet.haslayer(scapy.TCP):
                    protocol = "TCP"
                elif packet.haslayer(scapy.UDP):
                    protocol = "UDP"
                elif packet.haslayer(scapy.ICMP):
                    protocol = "ICMP"
            print(f"DEBUG: 收到 {protocol} 数据包")

        # if packet is None:
        #     if self.debug_mode:
        #         print("DEBUG: 收到None数据包, 跳过")
        #     return
        
        try:
            if self.debug_mode:
                print(f"DEBUG: 收到数据包，类型: {type(packet)}")
                print(f"DEBUG: 数据包摘要: {packet.summary() if hasattr(packet, 'summary') else 'No summary'}")
            
            # 安全地获取长度
            packet_length = 0
            try:
                packet_length = len(packet)
                if self.debug_mode:
                    print(f"DEBUG: 数据包长度: {packet_length}")
            except:
                if self.debug_mode:
                    print("DEBUG: 无法获取数据包长度")
                packet_length = 0
            
            # 更新统计
            self.packet_count += 1
            self.stats['total_packets'] = self.packet_count
            self.stats['bytes_received'] += packet_length
            
            # 添加启动时间记录
            if self.stats['start_time'] is None:
                import time
                self.stats['start_time'] = time.time()
            
        except Exception as e:
            if self.debug_mode:
                print(f"DEBUG: 处理数据包基础信息时出错: {e}")
            return  

        # 首先检查是否为IP分片
        is_fragment = False
        try:
            if packet.haslayer(IP):
                ip = packet[IP]
                is_fragment = ip.flags.MF or ip.frag > 0
                if self.debug_mode and is_fragment:
                    print(f"DEBUG: 检测到分片包: ID={ip.id}, frag={ip.frag}, MF={ip.flags.MF}")
        except Exception as e:
            if self.debug_mode:
                print(f"DEBUG: 检查分片时出错: {e}")

        # 处理IP分片重组
        reassembled_packet = None
        is_reassembled = False

        if is_fragment and self.ip_reassembler and hasattr(self.ip_reassembler, 'process_packet'):
            try:
                reassembled_packet = self.ip_reassembler.process_packet(packet)
                if reassembled_packet:
                    is_reassembled = True
                    if self.debug_mode:
                        print(f"DEBUG: 成功重组数据包！原始包: {packet.summary()}")
                        print(f"DEBUG: 重组后包: {reassembled_packet.summary()}")
                        print(f"DEBUG: 原始长度: {len(packet)}, 重组后长度: {len(reassembled_packet)}")
            except Exception as e:
                if self.debug_mode:
                    print(f"DEBUG: 分片重组时出错: {e}")
        
        # 如果有重组后的数据包，优先使用
        packet_to_parse = reassembled_packet if reassembled_packet else packet
        
        # 解析数据包
        parsed_packet = None
            
        try:
            # 确保packet_parser存在且可调用
            if self.packet_parser and hasattr(self.packet_parser, 'parse_packet'):
                parsed_packet = self.packet_parser.parse_packet(packet_to_parse, self.packet_count, is_reassembled=is_reassembled)
                
                if self.debug_mode:
                    print(f"DEBUG: 解析器返回类型: {type(parsed_packet)}")
                    print(f"DEBUG: 解析器返回值: {parsed_packet}")

                # 如果解析器没有设置重组标记，我们手动设置
                if is_reassembled:
                    parsed_packet['reassembled'] = True
                    # 确保描述字段正确
                    if 'summary' in parsed_packet:
                        if not parsed_packet['summary'].startswith('[Reassembled]'):
                            parsed_packet['summary'] = f"[Reassembled] {parsed_packet['summary']}"
                else:
                    parsed_packet['reassembled'] = False
                    
            else:
                parsed_packet = self._parse_packet_manually(packet, packet_length)
                parsed_packet['reassembled'] = False
                
        except Exception as e:
            if self.debug_mode:
                print(f"DEBUG: 解析数据包时出错: {e}")
            parsed_packet = self._parse_packet_manually(packet, packet_length)
            parsed_packet['reassembled'] = False
        
        # 确保解析结果包含正确的协议信息
        if not is_reassembled and packet.haslayer(IP):
            ip = packet[IP]
            is_fragment = ip.flags.MF or ip.frag > 0
            parsed_packet['is_fragment'] = is_fragment
            
            if is_fragment:
                # 分片包：设置正确的协议显示
                if ip.proto == 1:  # ICMP
                    parsed_packet['protocol'] = 'ICMP'
                else:
                    parsed_packet['protocol'] = 'IP'
        
        # 保存数据包
        self.captured_packets.append(parsed_packet)
        
        # 调用回调函数
        if callable(self.packet_handler):
            try:
                self.packet_handler(parsed_packet, self.stats)
            except Exception as e:
                if self.debug_mode:
                    print(f"DEBUG: 回调函数执行出错: {e}")

    def _create_default_packet(self, packet, length):
        """创建默认的数据包字典"""
        import time
        return {
            'index': self.packet_count,
            'length': length,
            'timestamp': time.time(),
            'protocol': 'Unknown',
            'summary': str(packet.summary()) if hasattr(packet, 'summary') else 'Raw Packet',
            'raw': str(packet)[:100] if hasattr(packet, '__str__') else 'No string representation'
        }
    
    def _convert_to_dict(self, obj, original_packet, length):
        """将任意对象转换为字典"""
        import time
        result = {
            'index': self.packet_count,
            'length': length,
            'timestamp': time.time()
        }
        
        if isinstance(obj, (list, tuple)):
            result['data'] = list(obj)
            result['protocol'] = 'List/Tuple'
        elif hasattr(obj, '__dict__'):
            result.update(obj.__dict__)
        elif isinstance(obj, str):
            result['data'] = obj
            result['protocol'] = 'String'
        else:
            result['data'] = str(obj)
            result['protocol'] = type(obj).__name__
            
        return result

    def _reset_scapy_state(self):
        """重置Scapy的全局状态"""
        try:
            # 关闭可能存在的Scapy套接字
            if hasattr(scapy, 'conf') and hasattr(scapy.conf, 'socket'):
                try:
                    if scapy.conf.socket:
                        scapy.conf.socket.close()
                        scapy.conf.socket = None
                except:
                    pass
            
            # 重置其他可能的状态
            scapy.conf.iface = None
            scapy.conf.sniff_promisc = True
            scapy.conf.promisc = True
            scapy.conf.use_pcap = False
            
        except Exception as e:
            print(f"重置Scapy状态时出错: {e}")

    def clear_packets(self):
        """清空捕获的数据包"""
        self.captured_packets.clear()
        self.packet_count = 0
        self.stats = {
            'total_packets': 0,
            'bytes_received': 0,
            'protocols': {},
            'start_time': None
        }
        
        # 同时清理分片重组器的缓存
        if hasattr(self, 'ip_reassembler') and self.ip_reassembler:
            # 如果 reassembler 有 clear 方法
            if hasattr(self.ip_reassembler, 'clear_cache'):
                self.ip_reassembler.clear_cache()
            # 或者重新创建一个新的
            else:
                from src.core.reassembler import IPReassembler
                self.ip_reassembler = IPReassembler()

    def get_packet(self, index):
        """获取指定索引的数据包"""
        if index >=0 and index < len(self.captured_packets):
            return self.captured_packets[index]
        return None

    def get_stats(self):
        """获取统计信息"""
        return self.stats.copy()
    
    def get_traffic_summary(self):
        """获取流量统计摘要"""
        stats = self.get_stats()
        
        # 添加人类可读的流量格式
        bytes_received = stats['bytes_received']
        if bytes_received < 1024:
            traffic_str = f"{bytes_received} B"
        elif bytes_received < 1024 * 1024:
            traffic_str = f"{bytes_received / 1024:.2f} KB"
        elif bytes_received < 1024 * 1024 * 1024:
            traffic_str = f"{bytes_received / (1024 * 1024):.2f} MB"
        else:
            traffic_str = f"{bytes_received / (1024 * 1024 * 1024):.2f} GB"
        
        return {
            'packets': stats['total_packets'],
            'bytes': stats['bytes_received'],
            'traffic_formatted': traffic_str,
            'protocols': stats['protocols']
        }
    
    def _ensure_string_values(self, data):
        """确保字典中的所有值都是字符串类型"""
        if isinstance(data, dict):
            result = {}
            for key, value in data.items():
                if isinstance(value, dict):
                    result[key] = self._ensure_string_values(value)
                elif isinstance(value, list):
                    result[key] = [str(item) if not isinstance(item, (dict, list)) else 
                                self._ensure_string_values(item) if isinstance(item, dict) else 
                                item for item in value]
                else:
                    result[key] = str(value)
            return result
        return data
    def _parse_packet_manually(self, packet, length):
        """手动解析数据包"""
        import time
        from scapy.all import IP, TCP, UDP, ICMP, ARP
        
        result = {
            'index': str(self.packet_count),  # 转换为字符串
            'length': str(length),  # 转换为字符串
            'timestamp': str(time.time()),  # 转换为字符串
            'protocol': 'Unknown',
            'summary': '',
            'src': '',
            'dst': '',
            'info': ''
        }
        
        # 尝试获取摘要
        if hasattr(packet, 'summary'):
            result['summary'] = packet.summary()[:200]
        
        # 解析协议层
        try:
            # 检查是否有IP层
            if IP in packet:
                result['protocol'] = 'IP'
                result['src'] = packet[IP].src
                result['dst'] = packet[IP].dst
                
                # 检查传输层协议
                if TCP in packet:
                    result['protocol'] = 'TCP'
                    result['info'] = f"Sport: {packet[TCP].sport} -> Dport: {packet[TCP].dport}"
                elif UDP in packet:
                    result['protocol'] = 'UDP'
                    result['info'] = f"Sport: {packet[UDP].sport} -> Dport: {packet[UDP].dport}"
                elif ICMP in packet:
                    result['protocol'] = 'ICMP'
                    result['info'] = f"Type: {packet[ICMP].type}"
            
            # 检查ARP
            elif ARP in packet:
                result['protocol'] = 'ARP'
                result['src'] = packet[ARP].psrc
                result['dst'] = packet[ARP].pdst
                result['info'] = f"Op: {packet[ARP].op}"
        
        except Exception as e:
            if self.debug_mode:
                print(f"DEBUG: 手动解析协议时出错: {e}")
            result['info'] = f"Parse error: {e}"
        
        return result

    def _reset_all_state(self):
        """完全重置嗅探器所有状态"""
        self.is_sniffing = False
        self.packet_count = 0
        self.captured_packets = []
        self.stats = {
            'total_packets': 0,
            'bytes_received': 0,
            'protocols': {},
            'start_time': None
        }
        self.sniff_params = None
        self.packet_handler = None
        
        # 清理 Scapy 状态
        self._cleanup_scapy()
        
        # 强制垃圾回收，清理残留对象
        import gc
        gc.collect()