import struct
from scapy.all import PcapReader, IP, IPv6, TCP, UDP
from .BasicPacketInfo import BasicPacketInfo
from .utils import IdGenerator

class PacketReader:
    """
    从PCAP文件读取数据包,并生成BasicPacketInfo格式的数据
    使用Scapy库进行解析
    """

    def __init__(self, filename):
        self.pcap_reader = PcapReader(filename)
        self.generator = IdGenerator()
        self.totGen = IdGenerator()

    def nextPacket(self):
        """
        Description: 生成下一个数据包
        Input: None
        Output: BasicPacketInfo
        """
        try:
            packet = self.pcap_reader.read_packet()
            if packet is None:
                print("No more packets to read.")
            while packet is not None:
                self.totGen.nextId()
                
                # 检查是否为TCP数据包
                if IP in packet:
                    if TCP in packet:
                        return self._process_ipv4_packet(packet)
                    elif UDP in packet:
                        return self._process_ipv4_udp_packet(packet)
                elif IPv6 in packet:
                    if TCP in packet:
                        return self._process_ipv6_packet(packet)
                    elif UDP in packet:
                        return self._process_ipv6_udp_packet(packet)
                
                print("Not a TCP or UDP packet.")
                packet = self.pcap_reader.read_packet()
                
        except EOFError:
            return None

    def _process_ipv4_packet(self, packet):
        """处理IPv4数据包"""
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        
        # 获取时间戳（转换为微秒）
        timestamp = int(packet.time * 1000000)
        
        # 获取TCP负载
        if tcp_layer.payload:
            payload = bytes(tcp_layer.payload)
        else:
            payload = b''
            
        return BasicPacketInfo(
            generator=self.generator,
            srcIP=ip_layer.src,
            dstIP=ip_layer.dst,
            srcPort=tcp_layer.sport,
            dstPort=tcp_layer.dport,
            protocol=ip_layer.proto,
            timeStamp=timestamp,
            headBytes=len(tcp_layer) - len(payload),
            payloadBytes=len(payload),
            flags=str(tcp_layer.flags),  # 将flags转换为字符串
            TCPWindow=tcp_layer.window,
            payload=payload
        )

    def _process_ipv6_packet(self, packet):
        """处理IPv6数据包"""
        ipv6_layer = packet[IPv6]
        tcp_layer = packet[TCP]
        
        # 获取时间戳（转换为微秒）
        timestamp = int(packet.time * 1000000)
        
        # 获取TCP负载
        if tcp_layer.payload:
            payload = bytes(tcp_layer.payload)
        else:
            payload = b''
            
        return BasicPacketInfo(
            generator=self.generator,
            srcIP=ipv6_layer.src,
            dstIP=ipv6_layer.dst,
            srcPort=tcp_layer.sport,
            dstPort=tcp_layer.dport,
            protocol=6,  # TCP protocol number
            timeStamp=timestamp,
            headBytes=len(tcp_layer) - len(payload),
            payloadBytes=len(payload),
            flags=str(tcp_layer.flags),  # 将flags转换为字符串
            TCPWindow=tcp_layer.window,
            payload=payload
        )
    def _process_ipv4_udp_packet(self, packet):
        """处理IPv4 UDP数据包"""
        ip_layer = packet[IP]
        udp_layer = packet[UDP]
        
        timestamp = int(packet.time * 1000000)
        
        if udp_layer.payload:
            payload = bytes(udp_layer.payload)
        else:
            payload = b''
            
        return BasicPacketInfo(
            generator=self.generator,
            srcIP=ip_layer.src,
            dstIP=ip_layer.dst,
            srcPort=udp_layer.sport,
            dstPort=udp_layer.dport,
            protocol=17,  # UDP protocol number
            timeStamp=timestamp,
            headBytes=8,  # UDP header is always 8 bytes
            payloadBytes=len(payload),
            flags="",  # UDP has no flags
            TCPWindow=0,  # UDP has no window
            payload=payload
        )
    def _process_ipv6_udp_packet(self, packet):
        """处理IPv6 UDP数据包"""
        ipv6_layer = packet[IPv6]
        udp_layer = packet[UDP]
        
        timestamp = int(packet.time * 1000000)
        
        if udp_layer.payload:
            payload = bytes(udp_layer.payload)
        else:
            payload = b''
            
        return BasicPacketInfo(
            generator=self.generator,
            srcIP=ipv6_layer.src,
            dstIP=ipv6_layer.dst,
            srcPort=udp_layer.sport,
            dstPort=udp_layer.dport,
            protocol=17,  # UDP protocol number
            timeStamp=timestamp,
            headBytes=8,  # UDP header is always 8 bytes
            payloadBytes=len(payload),
            flags="",  # UDP has no flags
            TCPWindow=0,  # UDP has no window
            payload=payload
        )