# 可视化
from datetime import datetime
from functools import partial
import sys
import threading
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, 
                            QWidget, QPushButton, QComboBox, QTableWidget, 
                            QTableWidgetItem, QTextEdit, QSplitter, QLabel,
                            QTabWidget, QHeaderView, QProgressBar, QMessageBox)
from PyQt5.QtCore import QTimer, Qt, pyqtSignal
from PyQt5.QtGui import QFont, QColor, QPalette
import time

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
        self.setGeometry(100, 100, 1600, 1000)

        # 设置应用样式
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QLabel {
                font-weight: bold;
                color: #333;
            }
            QPushButton {
                font-weight: bold;
                border-radius: 6px;
                padding: 8px 16px;
                font-size: 13px;
            }
            QComboBox {
                padding: 6px;
                border-radius: 4px;
                border: 1px solid #ccc;
                background-color: white;
            }
            QTextEdit {
                background-color: white;
                border: 1px solid #ccc;
                border-radius: 4px;
                padding: 8px;
            }
            QTableWidget {
                background-color: white;
                border: 1px solid #ccc;
                border-radius: 4px;
                alternate-background-color: #f9f9f9;
                gridline-color: #e0e0e0;
            }
            QHeaderView::section {
                background-color: #4a6fa5;
                color: white;
                font-weight: bold;
                padding: 8px;
                border: none;
            }
            QTabWidget::pane {
                border: 1px solid #ccc;
                background-color: white;
                border-radius: 6px;
            }
            QTabBar::tab {
                background-color: #e0e0e0;
                padding: 10px 20px;
                margin-right: 4px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background-color: #4a6fa5;
                color: white;
            }
            QStatusBar {
                background-color: #4a6fa5;
                color: white;
                font-weight: bold;
            }
        """)

        # 创建中央窗口部件
        central_widget = QWidget()
        central_widget.setStyleSheet("background-color: #f5f5f5;")
        self.setCentralWidget(central_widget)
        # 主布局
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(12)
        main_layout.setContentsMargins(20, 20, 20, 20)

        # 控制面板
        control_panel = QWidget()
        control_panel.setStyleSheet("""
            QWidget {
                background-color: white;
                border-radius: 10px;
                padding: 15px;
            }
        """)
        control_layout = QHBoxLayout(control_panel)
        control_layout.setSpacing(15)

        # 添加网卡选择
        interface_label = QLabel("网卡选择:")
        interface_label.setFont(QFont("Microsoft YaHei", 20))
        control_layout.addWidget(interface_label)
        self.interface_combo = QComboBox() # 创建网络接口选择下拉框
        self.interface_combo.setFont(QFont("Consolas", 18))
        self.interface_combo.setMinimumWidth(400)
        self.interface_combo.setMinimumHeight(40)
        self.interface_combo.setStyleSheet("""
            QComboBox {
                padding: 8px;
                font-size: 15px;
            }
            QComboBox QAbstractItemView {
                min-height: 30px; 
                padding: 8px; 
                font-size: 14px;
            }
        """)
        control_layout.addWidget(self.interface_combo)

        # 添加过滤条件
        filter_label = QLabel("过滤条件:")
        filter_label.setFont(QFont("Microsoft YaHei", 20))
        control_layout.addWidget(filter_label)
        self.filter_edit = QComboBox()
        self.filter_edit.setEditable(True)
        self.filter_edit.setFont(QFont("Consolas", 18))
        self.filter_edit.addItems(["", "tcp", "udp", "icmp", "arp", "port 80", "port 9999", "host 192.168.1.1"])
        self.filter_edit.setMinimumWidth(250)
        self.filter_edit.setStyleSheet("""
            QComboBox {
                padding: 8px;
                font-size: 15px;
            }
        """)
        control_layout.addWidget(self.filter_edit)

        # 添加开始按钮
        self.start_button = QPushButton("开始抓包")
        self.start_button.setFont(QFont("Microsoft YaHei", 20))
        self.start_button.setStyleSheet("""
            QPushButton {
                background-color: #28a745;
                color: white;
                border: 2px solid #218838;
            }
            QPushButton:hover {
                background-color: #218838;
            }
            QPushButton:pressed {
                background-color: #1e7e34;
            }
        """)

        # 添加停止按钮
        self.stop_button = QPushButton("停止抓包")
        self.stop_button.setFont(QFont("Microsoft YaHei", 20))
        self.stop_button.setStyleSheet("""
            QPushButton {
                background-color: #dc3545;
                color: white;
                border: 2px solid #c82333;
            }
            QPushButton:hover {
                background-color: #c82333;
            }
            QPushButton:pressed {
                background-color: #bd2130;
            }
        """)
        self.stop_button.setEnabled(False)

        # 添加清空按钮
        self.clear_button = QPushButton("清空数据")
        self.clear_button.setFont(QFont("Microsoft YaHei", 20))
        self.clear_button.setStyleSheet("""
            QPushButton {
                background-color: #6c757d;
                color: white;
                border: 2px solid #5a6268;
            }
            QPushButton:hover {
                background-color: #5a6268;
            }
            QPushButton:pressed {
                background-color: #545b62;
            }
        """)

        control_layout.addWidget(self.start_button)
        control_layout.addWidget(self.stop_button)
        control_layout.addWidget(self.clear_button)
        control_layout.addStretch()

        self.stats_label = QLabel("就绪")
        self.stats_label.setFont(QFont("Microsoft YaHei", 20, QFont.Bold))
        self.stats_label.setStyleSheet("color: #4a6fa5; padding: 8px;")
        control_layout.addWidget(self.stats_label)

        main_layout.addWidget(control_panel)

        # 创建标签页控件
        self.tabs = QTabWidget()
        self.tabs.setFont(QFont("Microsoft YaHei", 20))
        main_layout.addWidget(self.tabs)

        # 数据包列表标签页
        self.packet_tab = self.create_packet_tab()
        self.tabs.addTab(self.packet_tab, "数据包列表")

        # 统计信息标签页
        self.stats_tab = self.create_stats_tab()
        self.tabs.addTab(self.stats_tab, "统计信息")

        # 显示状态栏信息
        self.statusBar().showMessage("准备就绪, 请选择需要侦听的网卡并开始抓包")
        self.statusBar().setFont(QFont("Microsoft YaHei", 18))

    def create_packet_tab(self):
        """创建数据包列表标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(10)
        layout.setContentsMargins(10, 10, 10, 10)

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

        # 设置表格样式
        self.packet_table.setStyleSheet("""
            QTableWidget {
                font-size: 13px;
                selection-background-color: #cce5ff;
                selection-color: black;
            }
            QTableWidget::item {
                padding: 8px;
                min-height: 28px;
            }
        """)
        header_font = QFont("Microsoft YaHei", 14, QFont.Bold)  # 表头更大一些
        header = self.packet_table.horizontalHeader()
        header.setFont(header_font)
        # 设置行高
        self.packet_table.verticalHeader().setDefaultSectionSize(35) 

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
        splitter.setStyleSheet("""
            QSplitter::handle {
                background-color: #ccc;
                height: 4px;
            }
        """)
        # 数据包详情
        detail_widget = QWidget()
        detail_layout = QVBoxLayout(detail_widget)
        detail_label = QLabel("数据包详情:")
        detail_label.setFont(QFont("Microsoft YaHei", 22, QFont.Bold))
        detail_label.setStyleSheet("color: #2c3e50;")
        detail_layout.addWidget(detail_label)

        # 创建文本编辑框显示协议详情
        self.detail_text = QTextEdit()
        
        # 使用等宽字体, 便于对齐显示
        self.detail_text.setFont(QFont("Consolas", 15))
        self.detail_text.setStyleSheet("""
            QTextEdit {
                background-color: #f8f9fa;
                border: 2px solid #dee2e6;
                font-size: 12px;
            }
        """)
        detail_layout.addWidget(self.detail_text)

        # 原始数据
        raw_widget = QWidget()
        raw_layout = QVBoxLayout(raw_widget)
        raw_label = QLabel("原始数据: ")
        raw_label.setFont(QFont("Microsoft YaHei", 22, QFont.Bold))
        raw_label.setStyleSheet("color: #2c3e50;")
        raw_layout.addWidget(raw_label)
        
        self.raw_text = QTextEdit()
        self.raw_text.setFont(QFont("Consolas", 15))
        self.raw_text.setStyleSheet("""
            QTextEdit {
                background-color: #f8f9fa;
                border: 2px solid #dee2e6;
                font-size: 12px;
            }
        """)
        raw_layout.addWidget(self.raw_text)

        splitter.addWidget(detail_widget)
        splitter.addWidget(raw_widget)
        splitter.setSizes([500, 300])

        layout.addWidget(self.packet_table)
        layout.addWidget(splitter)
        
        return tab

    def create_stats_tab(self):
        """创建统计信息标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(15, 15, 15, 15)
        
        stats_label = QLabel("实时统计信息: ")
        stats_label.setFont(QFont("Microsoft YaHei", 20, QFont.Bold))
        stats_label.setStyleSheet("color: #2c3e50; margin-bottom: 15px;")
        layout.addWidget(stats_label)
        
        self.stats_text = QTextEdit()
        self.stats_text.setFont(QFont("Consolas", 11))
        self.stats_text.setStyleSheet("""
            QTextEdit {
                background-color: #f8f9fa;
                border: 2px solid #dee2e6;
                border-radius: 8px;
                padding: 15px;
                font-size: 13px;
                line-height: 1.5;
            }
        """)
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
        print(f"GUI: 开始捕获，当前线程数: {threading.active_count()}")
        self.stop_capture()
        time.sleep(0.1)
        self.clear_data()

        if self.interface_combo.currentIndex() == -1:
            QMessageBox.warning(self, "警告", "请先选择一个网络接口")
            return
        
        interface_name = self.interface_combo.currentData()
        # 获取并清理过滤条件
        filter_str = self.filter_edit.currentText().strip()  # 去除前后空格
        
        # 如果过滤条件为空字符串，设置为None
        if not filter_str:
            filter_str = ""
        
        print(f"GUI: 接口={interface_name}, 过滤条件='{filter_str}'")
        
        self.current_interface = interface_name
        self.current_filter = filter_str if filter_str else "无"
        print(f"开始抓包 - 接口: {interface_name}, 过滤: {self.current_filter}")

        self.capture_stats.update({
            'packet_count': 0,
            'bytes_received': 0,
            'start_time': datetime.now(),
            'interface': interface_name,
            'filter': self.current_filter
        })

        # 清空数据
        self.clear_data()
        
        # 开始新的捕获
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
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

        # 停止嗅探器
        if hasattr(self, 'packet_sniffer'):
            self.packet_sniffer.stop_sniffing()
            
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
            
            # 安全地获取数据
            number = str(packet.get('number', 'N/A'))
            timestamp = packet.get('timestamp', 'N/A')
            length = str(packet.get('length', 0))
            
            # 确定协议显示
            protocol = packet.get('protocol', 'Unknown')
            is_reassembled = packet.get('reassembled', False)
            is_fragment = packet.get('is_fragment', False)
            
            # 设置协议列显示
            if is_reassembled:
                protocol_display = f"[重组] {protocol}"
            elif is_fragment:
                protocol_display = f"[分片] {protocol}"
            else:
                protocol_display = protocol
            
            # 获取地址信息
            src_addr = packet.get('layers', {}).get('IP', {}).get('source_ip', 'N/A')
            dst_addr = packet.get('layers', {}).get('IP', {}).get('destination_ip', 'N/A')
            
            # 获取端口信息
            ports = 'N/A'
            if 'TCP' in packet.get('layers', {}):
                tcp = packet['layers']['TCP']
                ports = f"{tcp.get('source_port', '')} → {tcp.get('destination_port', '')}"
            elif 'UDP' in packet.get('layers', {}):
                udp = packet['layers']['UDP']
                ports = f"{udp.get('source_port', '')} → {udp.get('destination_port', '')}"
            
            # 获取描述（摘要）
            summary = packet.get('summary', '')
            
            # 设置表格项
            self.packet_table.setItem(row, 0, QTableWidgetItem(number))
            self.packet_table.setItem(row, 1, QTableWidgetItem(timestamp))
            self.packet_table.setItem(row, 2, QTableWidgetItem(str(src_addr)))
            self.packet_table.setItem(row, 3, QTableWidgetItem(str(dst_addr)))
            
            # 协议列
            protocol_item = QTableWidgetItem(protocol_display)
            if is_reassembled:
                protocol_item.setForeground(QColor(0, 128, 0))  # 绿色
                protocol_item.setBackground(QColor(220, 255, 220))  # 浅绿背景
            elif is_fragment:
                protocol_item.setForeground(QColor(255, 140, 0))  # 橙色
            self.packet_table.setItem(row, 4, protocol_item)
            
            self.packet_table.setItem(row, 5, QTableWidgetItem(length))
            
            # 端口列
            self.packet_table.setItem(row, 6, QTableWidgetItem(str(ports)))
            
            # 描述列
            description_item = QTableWidgetItem(summary)
            if is_reassembled:
                description_item.setBackground(QColor(220, 255, 220))  # 浅绿背景
            elif is_fragment:
                description_item.setBackground(QColor(255, 245, 220))  # 浅橙背景
            self.packet_table.setItem(row, 7, description_item)
            
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
        
        try:
            row = selected_items[0].row()
            
            # 方法1：直接使用行号（推荐）
            # 因为表格的行号从0开始，正好对应captured_packets的索引
            packet = self.packet_sniffer.get_packet(row)
            
            if packet:
                print(f"DEBUG: 获取到第{row}行的数据包")
                print(f"DEBUG: 数据包类型: {type(packet)}")
                print(f"DEBUG: 数据包键: {list(packet.keys())}")
                
                # 检查是否有layers键
                if 'layers' not in packet:
                    print(f"DEBUG: 数据包缺少layers键，可能为重组包或手动解析包")
                    print(f"DEBUG: 数据包内容: {str(packet)[:500]}")
                self.display_packet_details(packet)
            else:
                print(f"无法获取第{row}行的数据包")
                
        except Exception as e:
            print(f"选择数据包时出错: {e}")
            import traceback
            traceback.print_exc()

    def display_packet_details(self, packet):
        """显示数据包详情"""
        try:
            lines = []
            lines.append("=== 数据包详情 ===\n")

            # 基础信息
            lines.append("【基础信息】")
            lines.append(f"  编号: {packet.get('number', 'N/A')}")
            lines.append(f"  时间: {packet.get('timestamp', 'N/A')}")
            lines.append(f"  长度: {packet.get('length', 0)} 字节")
            lines.append(f"  协议: {packet.get('protocol', 'Unknown')}")

            # 检查是否为重组包
            if packet.get('reassembled', False):
                lines.append("  状态: [重组包]")
            elif packet.get('is_fragment', False):
                lines.append("  状态: [分片包]")
                if 'fragment_info' in packet:
                    lines.append(f"  分片信息: {packet['fragment_info']}")
            
            lines.append("")
            
            # 分层信息
            if 'layers' in packet and packet['layers']:
                for layer_name, layer_data in packet['layers'].items():
                    lines.append(f"【{layer_name} 层】")
                    
                    if isinstance(layer_data, dict):
                        for key, value in layer_data.items():
                            if key != 'description':
                                if isinstance(value, dict):
                                    lines.append(f"  {key}:")
                                    for sub_key, sub_value in value.items():
                                        lines.append(f"    {sub_key}: {sub_value}")
                                else:
                                    lines.append(f"  {key}: {value}")
                        
                        # 添加描述
                        if 'description' in layer_data:
                            lines.append(f"  描述: {layer_data.get('description', 'N/A')}")
                    else:
                        lines.append(f"  数据: {layer_data}")
                    lines.append("")
            else:
                lines.append("【原始数据】")
                lines.append("  无分层解析数据")
                lines.append("")
            
            # 原始数据/负载
            if 'payload' in packet:
                payload = packet['payload']
                lines.append("【负载数据】")
                lines.append(f"  大小: {payload.get('size', 0)} 字节")
                
                if 'text' in payload:
                    text_preview = payload['text']
                    if len(text_preview) > 200:
                        text_preview = text_preview[:200] + "..."
                    lines.append(f"  文本预览: {text_preview}")
                
                if 'hex' in payload:
                    hex_preview = payload['hex']
                    if len(hex_preview) > 100:
                        hex_preview = hex_preview[:100] + "..."
                    lines.append(f"  十六进制: {hex_preview}")
            
            # 十六进制转储
            if 'hexdump' in packet and packet['hexdump']:
                lines.append("\n【十六进制转储】")
                # 限制显示行数
                hexdump_lines = packet['hexdump'].split('\n')
                for i in range(min(20, len(hexdump_lines))):  # 最多显示20行
                    lines.append(hexdump_lines[i])
                if len(hexdump_lines) > 20:
                    lines.append(f"... 还有 {len(hexdump_lines)-20} 行未显示")
            
            # 显示其他可能存在的字段
            important_fields = ['src', 'dst', 'info', 'summary', 'fragment_id', 'fragment_offset']
            for field in important_fields:
                if field in packet and packet[field]:
                    lines.append(f"\n【{field.upper()}】")
                    lines.append(f"  {packet[field]}")
            
            detail_text = '\n'.join(lines)
            self.detail_text.setText(detail_text)
            
            # 设置原始数据
            if 'hexdump' in packet:
                self.raw_text.setText(packet['hexdump'])
            elif 'raw' in packet:
                self.raw_text.setText(str(packet['raw']))
            else:
                self.raw_text.setText("无原始数据")
            
        except Exception as e:
            error_msg = f"显示数据包详情时出错:\n{str(e)}\n\n数据包结构:\n{str(packet)[:500]}..."
            print(f"显示详情错误: {e}")
            import traceback
            traceback.print_exc()
            self.detail_text.setText(error_msg)
            self.raw_text.setText("")

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
            try:
                # 将统计信息转换为数值类型
                total_packets = int(stats.get('total_packets', 0))
                bytes_received = int(stats.get('bytes_received', 0))
            except (ValueError, TypeError):
                total_packets = 0
                bytes_received = 0
                
            stats_lines.append(f"  总数据包数: {total_packets}")
            stats_lines.append(f"  总字节数: {bytes_received}")

            # 速率信息
            if self.capture_stats.get('start_time') and total_packets > 0:
                duration_seconds = (datetime.now() - self.capture_stats['start_time']).total_seconds()
                if duration_seconds > 0:
                    packets_per_second = total_packets / duration_seconds
                    bytes_per_second = bytes_received / duration_seconds  # 使用转换后的数值
                    
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

            # 协议统计
            stats_lines.append(f"\n【协议分布】")
            try:
                protocols = stats.get('protocols', {})
                for protocol, count in protocols.items():
                    stats_lines.append(f"  {protocol}: {count}")
            except Exception as e:
                stats_lines.append(f"  协议信息: 获取失败 ({e})")

            stats_text = '\n'.join(stats_lines)
            self.stats_text.setText(stats_text)
            
        except Exception as e:
            error_msg = f"更新统计信息时出错:\n{str(e)}"
            print(f"统计信息更新错误: {e}")
            import traceback
            traceback.print_exc()
            self.stats_text.setText(error_msg)