# 可视化
from datetime import datetime
from functools import partial
import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, 
                             QWidget, QPushButton, QComboBox, QTableWidget, 
                             QTableWidgetItem, QTextEdit, QSplitter, QLabel,
                             QTabWidget, QHeaderView, QProgressBar, QMessageBox)
from PyQt5.QtCore import QTimer, Qt, pyqtSignal
from PyQt5.QtGui import QFont, QColor

class MainWindow(QMainWindow):
    def __init__(self, packet_sniffer, packer_parser):
        super().__init__()
        self.packet_sniffer = packet_sniffer
        self.packet_parser = packer_parser
        self.is_clearing = False
        self.current_interface = None
        self.current_filter = None
        self.capture_stats = {
            'packet_count': 0,
            'bytes_received': 0,
            'start_time': None,
            'interface': None,
            'filter': None
        }

        self.init_ui()
        self.init_signals()
        self.load_interfaces()

    def init_ui(self):
        """初始化 UI 界面"""
        self.setWindowTitle("网络数据包嗅探器")
        # 设置窗口初始位置和大小
        self.setGeometry(100, 100, 1400, 900)

        # 创建中央窗口部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        # 主布局
        main_layout = QVBoxLayout(central_widget)

        # 控制面板
        control_layout = QHBoxLayout()
        # 添加网卡选择
        control_layout.addWidget(QLabel("网卡选择:"))
        self.interface_combo = QComboBox() # 创建网络接口选择下拉框
        self.interface_combo.setMinimumWidth(300)
        control_layout.addWidget(self.interface_combo)

        # 添加过滤条件
        control_layout.addWidget(QLabel("过滤条件:"))
        self.filter_edit = QComboBox() # 创建过滤条件选择下拉框
        self.filter_edit.setEditable(True) # 允许用户输入自定义过滤条件
        self.filter_edit.addItems(["", "tcp", "udp", "icmp", "arp", "port 80", "port 443", "host 192.168.1.1"]) # 添加常用过滤器选项
        self.filter_edit.setMinimumWidth(200)
        control_layout.addWidget(self.filter_edit)

        # 添加开始按钮
        self.start_button = QPushButton("开始抓包")
        self.start_button.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; }")
        # 添加停止按钮
        self.stop_button = QPushButton("停止抓包")
        self.stop_button.setStyleSheet("QPushButton { background-color: #f44336; color: white; }")
        # 添加清空按钮
        self.clear_button = QPushButton("清空数据")

        control_layout.addWidget(self.start_button)
        control_layout.addWidget(self.stop_button)
        control_layout.addWidget(self.clear_button)
        control_layout.addStretch()

        self.stats_label = QLabel("就绪")
        control_layout.addWidget(self.stats_label)
        main_layout.addLayout(control_layout)

        # 创建标签页控件
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # 数据包列表标签页
        self.packet_tab = self.create_packet_tab()
        self.tabs.addTab(self.packet_tab, "数据包列表")

        # 统计信息标签页
        self.stats_tab = self.create_stats_tab()
        self.tabs.addTab(self.stats_tab, "统计信息")

        # 显示状态栏信息
        self.statusBar().showMessage("准备就绪, 请选择需要侦听的网卡并开始抓包")

    def create_packet_tab(self):
        """创建数据包列表标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # 创建数据包表格
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(8)  # 8列，对应8种数据包信息
        self.packet_table.setHorizontalHeaderLabels([
            "编号",
            "时间",
            "源地址",   
            "目标地址",
            "协议",
            "长度",
            "端口", 
            "描述" 
        ])

        # 设置列宽调整策略
        header = self.packet_table.horizontalHeader()
        # 前7列均根据内容调整宽度
        for i in range(7):
            header.setSectionResizeMode(i, QHeaderView.ResizeToContents)
        # 描述信息拉伸填充剩余空间
        header.setSectionResizeMode(7, QHeaderView.Stretch)

        # 设置表格选择行为: 选择整行而非单个单元格
        self.packet_table.setSelectionBehavior(QTableWidget.SelectRows)
        # 交替行颜色
        self.packet_table.setAlternatingRowColors(True)

        # 详情分割器
        splitter = QSplitter(Qt.Vertical)
        # 数据包详情
        detail_widget = QWidget()
        detail_layout = QVBoxLayout(detail_widget)
        detail_layout.addWidget(QLabel("数据包详情:"))
        # 创建文本编辑框显示协议详情
        self.detail_text = QTextEdit()
        # 使用等宽字体, 便于对齐显示
        self.detail_text.setFont(QFont("Consolas", 9))
        detail_layout.addWidget(self.detail_text)

        # 原始数据
        raw_widget = QWidget()
        raw_layout = QVBoxLayout(raw_widget)
        raw_layout.addWidget(QLabel("原始数据:"))
        self.raw_text = QTextEdit()
        self.raw_text.setFont(QFont("Consolas", 9))
        raw_layout.addWidget(self.raw_text)

        splitter.addWidget(detail_widget)
        splitter.addWidget(raw_widget)
        splitter.setSizes([400, 300])

        layout.addWidget(self.packet_table)
        layout.addWidget(splitter)
        
        return tab

    def create_stats_tab(self):
        """创建统计信息标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        self.stats_text = QTextEdit()
        self.stats_text.setFont(QFont("Consolas", 10))
        layout.addWidget(self.stats_text)
        
        return tab

    def init_signals(self):
        """初始化信号连接"""
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button.clicked.connect(self.stop_capture)
        self.clear_button.clicked.connect(self.clear_data)
        self.packet_table.itemSelectionChanged.connect(self.on_packet_selected)

    def load_interfaces(self):
        """加载网络接口"""
        interfaces = self.packet_sniffer.get_available_interfaces()
        self.interface_combo.clear()

        for itf in interfaces:
            display_text = f"{itf['name']} ({itf['ip']}) - {itf['status']}"
            self.interface_combo.addItem(display_text, itf['name'])

        if interfaces:
            self.statusBar().showMessage(f"找到{len(interfaces)}个网络接口")
        else:
            self.statusBar().showMessage("未找到可用的网络接口")

    def start_capture(self):
        """开始捕获数据包"""
        if self.interface_combo.currentIndex() == -1:
            QMessageBox.warning(self, "警告", "请先选择一个网络接口")
            return
        
        interface_name = self.interface_combo.currentData()
        filter_str = self.filter_edit.currentText()
        self.current_interface = interface_name
        self.current_filter = filter_str

        self.capture_stats.update({
            'packet_count': 0,
            'start_time': datetime.now(),
            'interface': interface_name,
            'filter': filter_str
        })

        # 设置数据包处理回调
        success = self.packet_sniffer.start_sniffing(
            interface=interface_name,
            packet_handler=self.on_packet_received,
            filter_str=filter_str
        )

        if success:
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.statusBar().showMessage(
                f"正在捕获数据包 - 接口: {interface_name}" + 
                f"过滤条件: {filter_str if filter_str else '无'}"
            )
        else:
            QMessageBox.critical(self, "错误", "无法开始捕获数据包")
            self.current_interface = None
            self.current_filter = None

    def stop_capture(self):
        """停止捕获数据包"""
        self.packet_sniffer.stop_sniffing()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        if self.capture_stats['start_time']:
            duration = datetime.now() - self.capture_stats['start_time']
            duration_str = str(duration).split('.')[0]
            self.statusBar().showMessage(
                f"捕获已停止 | " +
                f"接口: {self.current_interface} | " +
                f"时长: {duration_str} | " +
                f"数据包: {self.capture_stats['packet_count']}"
            )
        else:
            self.statusBar().showMessage("捕获已停止")

    def clear_data(self):
        """清空数据"""
        try:
            self.is_clearing = True
            if hasattr(self, 'packet_sniffer'):
                self.packet_sniffer.clear_packets()
            
            if hasattr(self, 'packet_table'):
                self.packet_table.setRowCount(0)
                self.packet_table.clearSelection()

            if hasattr(self, 'detail_text'):
                self.detail_text.clear()

            if hasattr(self, 'raw_text'):
                self.raw_text.clear()

            if hasattr(self, 'stats_text'):
                self.stats_text.clear()

            if hasattr(self, 'capture_stats'):
                self.capture_stats.update({
                    'packet_count': 0,
                    'start_time': None,
                    'interface': self.capture_stats.get('interface'),
                })

            self.statusBar().showMessage("数据已清空")

        except Exception as e:
            self.statusBar().showMessage(f"清空数据时出错: {str(e)}")
            print(f"清空数据错误: {e}")

        finally:
            self.is_clearing = False

    def on_packet_received(self, packet, stats):
        """处理接收到的数据包"""
        try:
            if hasattr(self, 'is_clearing') and self.is_clearing:
                return
            
            if hasattr(self, 'capture_stats'):
                self.capture_stats['packet_count'] = stats.get('total_packets', 0)
                self.capture_stats['bytes_received'] = stats.get('bytes_received', 0)

            if not self.stop_button.isEnabled():
                return # 停止按钮不可用表示未在捕获

            # 在主线程中更新UI
            update_func = partial(self.update_packet_table, packet, stats)
            QTimer.singleShot(0, update_func)
        
        except Exception as e:
            print(f"处理数据包时出错: {e}")

    def update_packet_table(self, packet, stats):
        """更新数据包表格"""
        try:
            row = self.packet_table.rowCount()
            self.packet_table.insertRow(row)
            
            # 安全地获取数据，避免KeyError
            number = str(packet.get('number', 'N/A'))
            timestamp = packet.get('timestamp', 'N/A')
            protocol = packet.get('protocol', 'Unknown')
            length = str(packet.get('length', 0))
            summary = packet.get('summary', '')
            
            # 设置表格项
            self.packet_table.setItem(row, 0, QTableWidgetItem(number))
            self.packet_table.setItem(row, 1, QTableWidgetItem(timestamp))
            
            # 安全地获取地址信息
            try:
                src_addr = self._get_source_address(packet)
                dst_addr = self._get_destination_address(packet)
            except Exception:
                src_addr = 'N/A'
                dst_addr = 'N/A'
            
            self.packet_table.setItem(row, 2, QTableWidgetItem(src_addr))
            self.packet_table.setItem(row, 3, QTableWidgetItem(dst_addr))
            self.packet_table.setItem(row, 4, QTableWidgetItem(protocol))
            self.packet_table.setItem(row, 5, QTableWidgetItem(length))
            
            # 获取端口信息
            try:
                ports = self._get_port_info(packet)
            except Exception:
                ports = 'N/A'
            
            self.packet_table.setItem(row, 6, QTableWidgetItem(ports))
            self.packet_table.setItem(row, 7, QTableWidgetItem(summary))
            
            # 自动滚动
            self.packet_table.scrollToBottom()
            
            # 更新统计
            self.update_stats_display(stats)
            self.stats_label.setText(f"数据包: {stats.get('total_packets', 0)}")
            
        except Exception as e:
            print(f"更新表格时出错: {e}")

    def _get_source_address(self, packet):
        """获取源地址"""
        layers = packet['layers']
        if 'IP' in layers:
            return layers['IP']['source_ip']
        elif 'Ethernet' in layers:
            return layers['Ethernet']['source_mac']
        elif 'ARP' in layers:
            return layers['ARP']['sender_ip']
        return 'N/A'

    def _get_destination_address(self, packet):
        """获取目标地址"""
        layers = packet['layers']
        if 'IP' in layers:
            return layers['IP']['destination_ip']
        elif 'Ethernet' in layers:
            return layers['Ethernet']['destination_mac']
        elif 'ARP' in layers:
            return layers['ARP']['target_ip']
        return 'N/A'

    def _get_port_info(self, packet):
        """获取端口信息"""
        layers = packet['layers']
        if 'TCP' in layers:
            return f"{layers['TCP']['source_port']} → {layers['TCP']['destination_port']}"
        elif 'UDP' in layers:
            return f"{layers['UDP']['source_port']} → {layers['UDP']['destination_port']}"
        return 'N/A'

    def on_packet_selected(self):
        """处理数据包选择事件"""
        selected_items = self.packet_table.selectedItems()
        if not selected_items:
            return
        
        row = selected_items[0].row()
        packet_number = int(self.packet_table.item(row, 0).text())
        
        packet = self.packet_sniffer.get_packet(packet_number - 1)
        if packet:
            self.display_packet_details(packet)

    def display_packet_details(self, packet):
        """显示数据包详情"""
        lines = []
        lines.append("=== 数据包详情 ===\n")
        
        for layer_name, layer_data in packet['layers'].items():
            lines.append(f"【{layer_name} 层】")
            
            for key, value in layer_data.items():
                if key != 'description':
                    if isinstance(value, dict):
                        lines.append(f"  {key}:")
                        for sub_key, sub_value in value.items():
                            lines.append(f"    {sub_key}: {sub_value}")
                    else:
                        lines.append(f"  {key}: {value}")
            
            lines.append(f"  描述: {layer_data.get('description', 'N/A')}")
            lines.append("")
        
        # 原始数据
        if 'payload' in packet:
            payload = packet['payload']
            lines.append("【负载数据】")
            lines.append(f"  大小: {payload['size']} 字节")
            lines.append(f"  文本预览: {payload['text'][:200]}")
            lines.append(f"  十六进制: {payload['hex'][:100]}...")  # 限制长度

        detail_text = '\n'.join(lines)
        self.detail_text.setText(detail_text)
        self.raw_text.setText(packet.get('hexdump', ''))

    def update_stats_display(self, stats):
        """更新统计信息显示"""
        try:
            stats_lines = []
            stats_lines.append("=== 实时统计信息 ===\n")

            # 基本抓包信息
            stats_lines.append("【捕获状态】")
            if self.capture_stats.get('start_time'):
                duration = datetime.now() - self.capture_stats['start_time']
                duration_str = str(duration).split('.')[0] # 去掉微秒部分
                stats_lines.append(f"  运行时长: {duration_str}")
            
            if self.current_interface:
                stats_lines.append(f"  监听网卡: {self.current_interface}")

            if self.current_filter:
                stats_lines.append(f"  过滤条件: {self.current_filter}")
            else:
                stats_lines.append("过滤条件: 无")

            # 数据包统计
            stats_lines.append(f"\n【数据包统计】")
            total_packets = stats.get('total_packets', 0)
            stats_lines.append(f"  总数据包数: {total_packets}")

            # 流量统计
            try:
                traffic_summary = self.packet_sniffer.get_traffic_summary()
            except Exception as e:
                print(f"获取流量摘要失败: {e}")
                traffic_summary = {
                    'packets': stats.get('total_packets', 0),
                    'bytes': 0,
                    'traffic_formatted': '0 B',
                    'protocols': stats.get('protocols', {})
                }
            # 速率信息
            if self.capture_stats.get('start_time') and total_packets > 0:
                duration_seconds = (datetime.now() - self.capture_stats['start_time']).total_seconds()
                if duration_seconds > 0:
                    packets_per_second = total_packets / duration_seconds
                    bytes_per_second = traffic_summary['bytes'] / duration_seconds
                    
                    stats_lines.append(f"\n【捕获速率】")
                    stats_lines.append(f"  包速率: {packets_per_second:.2f} 包/秒")
                    
                    # 显示带宽使用情况
                    if bytes_per_second < 1024:
                        bandwidth_str = f"{bytes_per_second:.2f} B/s"
                    elif bytes_per_second < 1024 * 1024:
                        bandwidth_str = f"{bytes_per_second / 1024:.2f} KB/s"
                    else:
                        bandwidth_str = f"{bytes_per_second / (1024 * 1024):.2f} MB/s"
                    
                    bits_per_second = bytes_per_second * 8
                    if bits_per_second < 1000:
                        bps_str = f"{bits_per_second:.2f} bps"
                    elif bits_per_second < 1000000:
                        bps_str = f"{bits_per_second / 1000:.2f} Kbps"
                    else:
                        bps_str = f"{bits_per_second / 1000000:.2f} Mbps"
                    
                    stats_lines.append(f"  数据速率: {bandwidth_str}")
                    stats_lines.append(f"  带宽占用: {bps_str}")    

            stats_text = '\n'.join(stats_lines)
            self.stats_text.setText(stats_text)
            
        except Exception as e:
            error_msg = f"更新统计信息时出错:\n{str(e)}"
            print(f"统计信息更新错误: {e}")
            self.stats_text.setText(error_msg)