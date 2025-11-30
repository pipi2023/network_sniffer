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
            'status': '活动' if is_up else '非活动',
            'is_up': is_up
        }

    except Exception as e:
        print(f"获取接口信息失败 {interface_name}: {e}")
        return None