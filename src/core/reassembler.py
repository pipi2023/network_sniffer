# IP 分片重组模块
import time
from scapy.all import IP, Raw, ICMP, Ether
from collections import defaultdict

class IPReassembler:
    """IP 分片重组模块"""
    def __init__(self, timeout=30):
        self.timeout = timeout
        self.fragments = defaultdict(dict) # (src, dst, id) -> {offset: packet}
        self.creation_times = {}

    def process_packet(self, packet):
        """处理数据包，检查是否需要重组"""
        # 非 IP 数据包，直接返回
        if not packet.haslayer(IP):
            return packet  
        
        ip = packet[IP]

        # 不是分片包，直接返回
        if ip.frag == 0 and not ip.flags.MF:
            return packet
        
        # 对于分片包，调用分片处理方法
        return self._process_fragment(packet)
        
    def _process_fragment(self, ip_packet):
        """处理IP分片"""
        key = (ip_packet.src, ip_packet.dst, ip_packet.id)
        offset = ip_packet.frag * 8 # 偏移量换成以字节为单位

        self._cleanup_fragments()
        self.fragments[key][offset] = ip_packet
        self.creation_times[key] = time.time()

        # 检查是否可以重组
        reassembled = self._try_reassemble(key)
        if reassembled:
            # 清缓存
            del self.fragments[key]
            del self.creation_times[key]
            return reassembled

        return None

    def _try_reassemble(self, key):
        """尝试重组分片"""
        fragments = self.fragments[key]
        if not fragments:
            return None
        
        print(f"DEBUG: 尝试重组 key={key}, 分片数量={len(fragments)}")

        offsets = sorted(fragments.keys())

        # 打印所有分片信息
        for offset in offsets:
            frag = fragments[offset]
            print(f"  Offset {offset}: ID={frag.id}, MF={frag.flags.MF}, len={len(frag)}")

        # 检查最后一个分片
        last_packet = None
        for offset in offsets:
            if fragments[offset].flags.MF == 0:
                last_packet = fragments[offset]
                print(f"DEBUG: 找到最后一个分片 at offset {offset}")
                break
        
        if not last_packet:
            print("DEBUG: 没有找到最后一个分片(MF=0), 无法重组")
            return None

        return self._reassemble_packets(key, offsets)        
            
    def _reassemble_packets(self, key, offsets):
        """重组数据包"""
        fragments = self.fragments[key]
        
        # 获取第一个分片作为基础
        first_offset = offsets[0]
        first_fragment = fragments[first_offset]
        
        # 找到最后一个分片
        last_fragment = None
        for offset in offsets:
            if fragments[offset].flags.MF == 0:
                last_fragment = fragments[offset]
                break
        
        if not last_fragment:
            print(f"ERROR: 在_reassemble_packets中没有找到最后一个分片")
            return None
        
        print(f"DEBUG: 重组 - 第一个分片: offset={first_offset}, 最后一个分片: offset={last_fragment.frag*8}")
        
        # 收集所有分片的数据
        reassembled_data = bytearray()
        for offset in sorted(offsets):
            fragment = fragments[offset]
            ip_header_len_frag = fragment.ihl * 4
            
            # 获取数据部分（IP层之后的所有内容）
            if fragment.haslayer(Raw):
                data = bytes(fragment[Raw])
            else:
                # 如果没有 Raw 层，获取 IP 负载
                data = bytes(fragment)[ip_header_len_frag:]
            
            print(f"DEBUG: 添加分片 offset={offset}, 数据长度={len(data)}")
            reassembled_data.extend(data)
        
        print(f"DEBUG: 总重组数据长度: {len(reassembled_data)}")
        
        # 创建重组后的包 - 正确的方法
        try:
            base_ip = first_fragment[IP]
        
            # 方法1：手动构建新的IP包（最可靠）
            # 获取IP头部信息
            ip_header = bytearray(bytes(base_ip)[:base_ip.ihl * 4])
            
            # 更新IP头部中的总长度字段（偏移2-3字节）
            total_length = len(ip_header) + len(reassembled_data)
            ip_header[2:4] = total_length.to_bytes(2, 'big')
            
            # 清除分片相关标志位（偏移6-7字节）
            # 第6字节的高3位是标志位，第7字节是分片偏移高8位
            flags_and_fragment = int.from_bytes(ip_header[6:8], 'big')
            # 清除MF标志和分片偏移
            flags_and_fragment &= 0b11111111  # 清除分片偏移高5位
            flags_and_fragment &= 0b11011111  # 清除MF标志
            ip_header[6:8] = flags_and_fragment.to_bytes(2, 'big')
            
            # 清空校验和（让系统重新计算）
            ip_header[10:12] = b'\x00\x00'
            
            # 构建完整的重组包
            reassembled_bytes = bytes(ip_header) + reassembled_data
            
            # 让scapy解析这个包
            reassembled_packet = IP(reassembled_bytes)
            
            print(f"DEBUG: 重组包创建成功，总长度: {len(reassembled_packet)}")
            
            # 重新计算校验和
            del reassembled_packet.chksum
            
            # 添加以太网层（如果有）
            # if first_fragment.haslayer(Ether):
            #     eth = Ether(bytes(first_fragment[Ether]))
            #     reassembled_packet = eth / reassembled_packet
            #     print(f"DEBUG: 添加Ethernet层")
            
            return reassembled_packet
            
        except Exception as e:
            print(f"DEBUG: 重组过程中出错: {e}")
            import traceback
            traceback.print_exc()
            return None


    def _cleanup_fragments(self):
        """清理过期分片"""
        current_time = time.time()
        expired_keys = []

        for key, create_time in list(self.creation_times.items()):
            if current_time - create_time > self.timeout:
                expired_keys.append(key)

        for key in expired_keys:
            if key in self.fragments:
                del self.fragments[key]
            if key in self.creation_times:
                del self.creation_times[key]

        return len(expired_keys)

    def get_fragment_info(self):
        """获取当前分片信息"""
        info = {}

        for key, fragments in self.fragments.items():
            src, dst, id = key
            info[f"{src} -> {dst} (ID: {id})"] = {
                'fragment_count': len(fragments),
                'offsets': sorted(fragments.keys()),
                'age': time.time() - self.creation_times[key]
            }

        return info
