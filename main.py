# 网络嗅探器主程序入口
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from PyQt5.QtWidgets import QApplication
from src.ui.gui import MainWindow
from src.core.sniffer import PacketSniffer
from src.core.parser import ProtocolParser
from src.core.reassembler import IPReassembler

def main():
    print("网络嗅探器启动...")
    try:
        # 创建QApplication实例
        app = QApplication(sys.argv)
        app.setApplicationName("网络嗅探器")
        app.setApplicationVersion("1.0.0")

        # 创建核心组件
        packet_parser = ProtocolParser()
        ip_reassembler = IPReassembler()
        packet_sniffer = PacketSniffer(packet_parser, ip_reassembler)

        # 创建主窗口
        main_window = MainWindow(packet_sniffer, packet_parser)
        main_window.show()

        # 运行应用
        return app.exec_()
    
    except Exception as e:
        print(f"启动应用程序时出错: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())