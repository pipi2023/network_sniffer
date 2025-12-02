# IP 分片重组模块
import time
from scapy.all import IP, Raw
from collections import defaultdict

class IPReassembler:
    """IP 分片重组模块"""
    def __init__(self, timeout=30):
        self.tomeout = timeout
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
        return self._process_fragment(ip)
        
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
        
        # # 检查分片是否连续
        # current_offset = 0
        # for offset in offsets:
        #     if offset > current_offset:
        #         return None
            
        #     ip_header_length  = fragments[offset].ihl * 4
        #     data_length = len(fragments[offset]) - ip_header_length
        #     current_offset = offset + data_length

        # # 检查是否覆盖了从0到最后一个字节的完整范围
        # for offset in offsets:
        #     if not fragments[offset].flags.MF:
        #         last_packet = fragments[offset]
        #         break

        # if last_packet and current_offset >= (last_packet.frag * 8 + len(last_packet) - last_packet.ihl * 4):
        #     return self._reassemble_packets(key, offsets)
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
        last_packet = None
        for offset in offsets:
            if fragments[offset].flags.MF == 0:
                last_packet = fragments[offset]
            break
    
        total_length = last_packet.frag * 8 + (len(last_packet) - last_packet.ihl * 4)
        reassembled_data = bytearray(total_length)

        for offset in offsets:
            fragment = fragments[offset]
            ip_header_len = fragment.ihl * 4

            data = bytes(fragment)[ip_header_len:]
            reassembled_data[offset:offset + len(data)] = data

        first_fragment = fragments[offsets[0]]
        reassembled_packet = IP(bytes(first_fragment))
        reassembled_packet.len = first_fragment.ijl * 4 + total_length
        reassembled_packet.flags = 0
        reassembled_packet.frag = 0
        reassembled_packet.chksum = None # 自动重新计算
        reassembled_packet.payload = Raw(reassembled_data)

        return reassembled_packet


    def _cleanup_fragments(self):
        """清理过期分片"""
        current_time = time.time()
        expired_keys = []

        for key, create_time in list(self.creation_times.items()):
            if current_time - create_time > self.tomeout:
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
