# IP 分片重组模块
import time
from scapy.all import IP, Raw
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
        
        offsets = sorted(fragments.keys())
        # 检查最后一个分片
        last_packet = None
        for offset in offsets:
            if fragments[offset].flags.MF == 0:
                last_packet = fragments[offset]
                break
        
        if not last_packet:
            return None
      
        total_length = last_packet.frag * 8 + (len(last_packet) - last_packet.ihl * 4)
        coverage = [False] * total_length
        for offset in offsets:
            fragment = fragments[offset]
            ip_header_len = fragment.ihl * 4
            data_len = len(fragment) - ip_header_len

            if offset + data_len > total_length:
                return None
            
            for i in range(data_len):
                if coverage[offset + i]:
                    return None # 发现重叠分片
                coverage[offset + i] = True

        if all(coverage):
            return self._reassemble_packets(key, offsets)
        
        return None

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
            return None
        
        # 计算总数据长度
        ip_header_len = first_fragment.ihl * 4
        data_length = 0
        
        # 计算总数据长度（所有分片的数据部分之和）
        reassembled_data = bytearray()
        for offset in sorted(offsets):
            fragment = fragments[offset]
            ip_header_len_frag = fragment.ihl * 4
            
            # 获取数据部分（IP层之后的所有内容）
            if fragment.haslayer(Raw):
                data = bytes(fragment[Raw])
            else:
                # 如果没有 Raw 层，可能是其他协议
                # 获取 IP 负载
                data = bytes(fragment)[ip_header_len_frag:]
            
            reassembled_data.extend(data)
            data_length += len(data)
        
        # 创建重组后的包
        reassembled_packet = IP(bytes(first_fragment))
        
        # 更新 IP 头部字段
        reassembled_packet.len = ip_header_len + data_length
        reassembled_packet.flags = 0  # 清除分片标志
        reassembled_packet.frag = 0   # 清除分片偏移
        
        # 设置负载
        reassembled_packet.payload = Raw(reassembled_data)
        
        # 删除校验和，让 scapy 自动计算
        del reassembled_packet.chksum
        if reassembled_packet.haslayer(Raw):
            del reassembled_packet[Raw].chksum
        
        return reassembled_packet


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
