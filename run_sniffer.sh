#!/bin/bash
# WSL网络嗅探器启动脚本

echo "=== WSL网络嗅探器启动 ==="
echo "内核: $(uname -r)"

# 设置GUI环境变量
export DISPLAY=":0"
export XDG_RUNTIME_DIR="/run/user/$(id -u)"
export QT_QPA_PLATFORM="xcb"
export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u)/bus"

# 如果XDG_RUNTIME_DIR不存在，创建它
if [ ! -d "$XDG_RUNTIME_DIR" ]; then
    echo "创建XDG_RUNTIME_DIR: $XDG_RUNTIME_DIR"
    sudo mkdir -p "$XDG_RUNTIME_DIR"
    sudo chown $(id -u):$(id -g) "$XDG_RUNTIME_DIR"
    sudo chmod 700 "$XDG_RUNTIME_DIR"
fi

# 设置Python路径
export PYTHONPATH="$PYTHONPATH:$(pwd)/src"

# 检查是否为WSL
if grep -q Microsoft /proc/version; then
    echo "检测到WSL环境"
    WSL_VERSION=$(cat /proc/version | grep -o 'WSL2' || echo 'WSL1')
    echo "WSL版本: $WSL_VERSION"
    
    # 修复WSL特定问题
    echo "应用WSL特定修复..."
    
    # 创建Scapy配置文件
    cat > ~/.scapy_wsl_config.py << 'EOF'
import platform
from scapy.config import conf

# WSL特定配置
conf.use_pcap = False
conf.L3socket = conf.L3socket

# 减少调试输出
conf.verb = 0

# 设置默认接口（WSL中可能是eth0）
try:
    from scapy.arch import get_if_list
    interfaces = get_if_list()
    if interfaces:
        conf.iface = interfaces[0]
except:
    pass
EOF
    
    # 临时修复Scapy的WSL问题
    export SCAPY_CONFIG=~/.scapy_wsl_config.py
fi

# 检查权限
if [ "$EUID" -ne 0 ]; then 
    echo "⚠️ 需要root权限进行网络捕获"
    echo "正在使用sudo重新启动..."
    exec sudo -E env DISPLAY="$DISPLAY" XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" "$0"
fi

# 最终启动命令
echo "启动网络嗅探器..."
python3 main.py