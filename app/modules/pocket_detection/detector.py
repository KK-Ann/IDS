#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import threading
import logging
import json
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP,Ether
from scapy.layers.http import HTTP
from scapy.utils import wrpcap

logger = logging.getLogger(__name__)

class TrafficDetector:
    def __init__(self, interface=None):
        self.interface = interface  # 如果为None，则会监听所有接口
        self.is_running = False
        self.capture_thread = None
        self.packet_stats = {
            #'total': 0,
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'http': 0,
            'other': 0
        }
        self.traffic_data = []
        self.suspicious_ips = set()
        self.packet_callback = None  # 可以设置回调来处理捕获的数据包
        
        # 创建保存流量数据的目录
        os.makedirs('data/traffic', exist_ok=True)
    
    def set_packet_callback(self, callback):
        """设置数据包处理回调函数"""
        self.packet_callback = callback
    
    def process_packet(self, packet):
        """处理捕获的数据包"""
        # 更新计数
        #self.packet_stats['total'] += 1
        
        # 提取和分析数据包
        packet_info = self._extract_packet_info(packet)
        
        # 保存流量数据
        if packet_info:
            self.traffic_data.append(packet_info)
            
            # 定期保存流量数据，防止内存占用过多
            if len(self.traffic_data) >= 1000:
                self._save_traffic_data()
                self._save_recent_pcap()
                self.traffic_data = []
        
        # 如果有设置回调，调用回调函数
        if self.packet_callback:
            self.packet_callback(packet)
    
    def _extract_packet_info(self, packet):
        """提取数据包的关键信息"""
        packet_type = 'other'
        src_ip = dst_ip = 'unknown'
        src_port = dst_port = 0
        protocol = 'unknown'
        payload_size = 0
        src_mac = dst_mac = 'unknown'

        try:
            # 提取MAC地址
            if Ether in packet:
                src_mac= packet[Ether].src
                dst_mac = packet[Ether].dst

            # 检查是否包含IP层
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # TCP数据包
                if TCP in packet:
                    packet_type = 'tcp'
                    self.packet_stats['tcp'] += 1
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    protocol = 'TCP'
                    
                    # 检查是否是HTTP
                    if packet.haslayer(HTTP) or dst_port == 80 or dst_port == 443:
                        packet_type = 'http'
                        self.packet_stats['http'] += 1
                        protocol = 'HTTP/HTTPS'
                
                # UDP数据包
                elif UDP in packet:
                    packet_type = 'udp'
                    self.packet_stats['udp'] += 1
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    protocol = 'UDP'
                
                # ICMP数据包
                elif ICMP in packet:
                    packet_type = 'icmp'
                    self.packet_stats['icmp'] += 1
                    protocol = 'ICMP'
                
                # 计算载荷大小
                if hasattr(packet, 'payload'):
                    payload_size = len(packet.payload)
                
                # 返回数据包信息
                return {
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_mac': src_mac,
                    'dst_mac': dst_mac,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'size': payload_size,
                    'type': packet_type,
                    'raw': packet.copy().build().hex()
                }
            
        except Exception as e:
            logger.error(f"数据包处理错误: {str(e)}")
        
        return None
    
    def analyze_packet(self, raw_hex):
        """分析数据包的所有协议层（类似Wireshark的协议分层结构）"""
        try:
            raw_bytes = bytes.fromhex(raw_hex)
            packet = Ether(raw_bytes)
            protocols = []

            # 遍历所有协议层
            for layer in packet.layers():
                # 跳过Raw协议层
                if layer.__name__ == 'Raw':
                    continue
                layer_instance = packet.getlayer(layer)
                if not layer_instance:
                    continue

                # 提取协议字段
                fields = {}
                for field_name in layer_instance.fields:
                    try:
                        field_value = getattr(layer_instance, field_name)
                        
                        # 特殊处理字节类型的字段
                        if isinstance(field_value, bytes):
                            # 过滤掉二进制负载数据
                            if field_name in ['load', 'payload']:
                                continue
                            # 将字节转换为可读格式
                            field_value = field_value.hex()
                            
                        # 处理时间戳字段
                        elif isinstance(field_value, (int, float)) and 'time' in field_name.lower():
                            field_value = datetime.fromtimestamp(field_value).isoformat()
                            
                        fields[field_name] = str(field_value)
                    except Exception as e:
                        logger.debug(f"解析字段 {field_name} 失败: {str(e)}")

                # 添加协议信息
                if fields:
                    protocols.append({
                        "name": layer.__name__,
                        "fields": fields
                    })
            
            return {"protocols": protocols}
            
        except Exception as e:
            logger.error(f"数据包分析错误: {str(e)}")
            return None
        
    def _save_traffic_data(self):
        """保存流量数据到文件"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'data/traffic/traffic_{timestamp}.json'
            with open(filename, 'w') as f:
                json.dump(self.traffic_data, f)
            logger.info(f"已保存流量数据到 {filename}，共 {len(self.traffic_data)} 条记录")
        except Exception as e:
            logger.error(f"保存流量数据失败: {str(e)}")
    
    def _save_recent_pcap(self, total=1000, chunk_size=100):
        """将前total个数据包按chunk_size分块保存为多个PCAP文件
        
        Args:
            total (int): 总数据包数量
            chunk_size (int): 每个PCAP文件包含的数据包数
        """
        try:
            # 获取数据包记录（线程安全）
            with threading.Lock():
                target_data = self.traffic_data[:total].copy()
            
            # 计算分块数量
            num_chunks = len(target_data) // chunk_size + (1 if len(target_data) % chunk_size else 0)
            saved_files = []
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

            # 分块处理
            for i in range(num_chunks):
                start = i * chunk_size
                end = start + chunk_size
                chunk = target_data[start:end]

                # 生成文件名
                filename = f'data/pcap/{timestamp}_{i+1:02d}.pcap'

                # 重建数据包
                packets = []
                for entry in chunk:
                    try:
                        packets.append(Ether(bytes.fromhex(entry['raw'])))
                    except Exception as e:
                        logger.error(f"数据包重建失败 [{entry['timestamp']}]: {str(e)}")

                # 保存文件
                if packets:
                    wrpcap(filename, packets)
                    saved_files.append({
                        "filename": filename,
                        "packets": len(packets),
                        "time_range": f"{chunk[0]['timestamp']} - {chunk[-1]['timestamp']}"
                    })
                    logger.info(f"成功保存 {filename} ({len(packets)} 个数据包)")

            return {
                "total_packets": len(target_data),
                "saved_files": saved_files,
                "success": bool(saved_files)
            }

        except Exception as e:
            logger.error(f"分块保存失败: {str(e)}")
            return {"success": False, "error": str(e)}
    def start_capture(self):
        """开始捕获网络流量"""
        if not self.is_running:
            self.is_running = True
            self.capture_thread = threading.Thread(target=self._capture_traffic)
            self.capture_thread.daemon = True
            self.capture_thread.start()
            logger.info(f"流量捕获已启动，监听接口: {self.interface or '所有'}")
    
    def _capture_traffic(self):
        """捕获网络流量的线程函数"""
        try:
            sniff(
                iface=self.interface,
                prn=self.process_packet,
                store=0,  # 不存储数据包，以节省内存
                stop_filter=lambda p: not self.is_running  # 当self.is_running为False时停止
            )
        except Exception as e:
            logger.error(f"流量捕获错误: {str(e)}")
            self.is_running = False
    
    def stop_capture(self):
        """停止捕获网络流量"""
        if self.is_running:
            self.is_running = False
            if self.capture_thread:
                self.capture_thread.join(timeout=2)
            self._save_traffic_data()  # 保存剩余的流量数据
            logger.info("流量捕获已停止")
    
    def get_traffic_stats(self):
        """获取数据包协议统计信息"""
        return self.packet_stats
    
    def get_recent_traffic(self, limit=0):
        """获取最近捕获的数据包数据"""
        if limit > 0:
            return self.traffic_data[-limit:]
        else:
            return self.traffic_data


# 用于测试
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    detector = TrafficDetector()# 初始化
    detector.start_capture()# 开始捕获
    
    try:
        # 持续运行10秒
        time.sleep(10)
    finally:
        detector.stop_capture()
        print("流量统计:", detector.get_traffic_stats())

