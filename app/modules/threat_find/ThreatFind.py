import csv
import pandas as pd
import numpy as np
from .flow_feature.PacketReader import PacketReader
from .flow_feature.FlowGenerator import FlowGenerator
from .flow_feature.FlowFeature import *
import joblib
import pickle
from datetime import datetime

class ThreatFind(object):
    def __init__(self, pcap_file="test2.pcap", socketio=None,
                 model_path="randomforest_model.pkl", pipeline_path="preprocessing_pipeline.pkl"):
        self.file_path = pcap_file
        self.flowTimeout = 120000000
        self.activityTimeout = 5000000
        self.subFlowTimeout = 1000000
        self.bulkTimeout = 1000000
        self.socketio = socketio # 连接服务器
        self.features_dict = [] # 流量特征字典的集合

        # 加载模型和预处理器
        with open(pipeline_path, 'rb') as f:
            pipe = pickle.load(f)
            self.scaler = pipe['scaler']
            self.pca = pipe['pca']
            self.label_encoder = pipe['label_encoder']
            print("Available threat classes:", self.get_threat_classes())
        self.model = joblib.load(model_path)
       # 协议映射字典
        self.protocol_mapping = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            0: 'Unknown'
        }
        # 威胁类型映射字典
        self.threat_mapping = {
            'BENIGN': '正常流量',
            'Bot': '僵尸网络',
            'DDoS': 'DDoS攻击',
            'DoS GoldenEye': 'GoldenEye DoS攻击',
            'DoS Hulk': 'Hulk DoS攻击',
            'DoS Slowhttptest': 'Slowhttp DoS攻击',
            'DoS slowloris': 'Slowloris DoS攻击',
            'FTP-Patator': 'FTP暴力破解',
            'Heartbleed': 'Heartbleed漏洞攻击',
            'Infiltration': '渗透攻击',
            'PortScan': '端口扫描',
            'SSH-Patator': 'SSH暴力破解'
        }
        
        # 威胁等级映射
        self.severity_mapping = {
            'BENIGN': '低',
            'PortScan': '中',
            'FTP-Patator': '中',
            'SSH-Patator': '中',
            'DoS Slowhttptest': '高',
            'DoS slowloris': '高',
            'DoS GoldenEye': '高',
            'DoS Hulk': '高',
            'DDoS': '高',
            'Bot': '高',
            'Infiltration': '高',
            'Heartbleed': '高'
        }

    def get_threat_classes(self):
        """返回所有可能的威胁类型标签"""
        if hasattr(self.label_encoder, 'classes_'):
            return list(self.label_encoder.classes_)
        return []
    def extractFeature(self,pcap_file=None):
        if pcap_file != None :
            self.file_path=pcap_file
        packetReader = PacketReader(self.file_path)
        flowGenerator = FlowGenerator(self.flowTimeout, self.activityTimeout, self.subFlowTimeout, self.bulkTimeout)

        basicPacket = packetReader.nextPacket()
        if basicPacket == None:
            print("None")
        while basicPacket != None:
            flowGenerator.addPacket(basicPacket)
            basicPacket = packetReader.nextPacket()
        flowGenerator.clearFlow()
        flowGenerator.dumpFeatureToCSV("data/test.csv") # 保存到csv中
        self.features_dict=flowGenerator.get_features_dict() # 得到得时一个数组，数组中得每一项是字典

        # return flowGenerator.get_features_dict()
    def getFeatures(self):
        # 筛选关键字段并转换numpy类型
        selected_features = []
        for feature in self.features_dict:
            filtered = {
                'Src IP': feature.get('Source IP', ''),
                'Dst IP': feature.get('Destination IP', ''),
                'Src Port': int(feature.get('Source Port', 0)),
                'Dst Port': int(feature.get('Destination Port', 0)),
                'Protocol': self.protocol_mapping.get(int(feature.get('Protocol', 0)), 'Unknown'),
                'Fwd Pkts/s': int(feature.get('Fwd Packets/s', 0)),
                'Bwd Pkts/s': int(feature.get('Bwd Packets/s', 0)),
                'Total Length of Fwd Packets': int(feature.get('Total Length of Fwd Packets', 0)),
                'Total Length of Bwd Packets': int(feature.get('Total Length of Bwd Packets', 0)),
                'Flow Duration(ms)': float(feature.get('Flow Duration', 0)),
                'FIN Count': int(feature.get('FIN Flag Count', 0)),
                'SYN Count': int(feature.get('SYN Flag Count', 0)),
                'RST Count': int(feature.get('RST Flag Count', 0)),
                'ACK Count': int(feature.get('ACK Flag Count', 0)),
            }
            selected_features.append(filtered)
        return selected_features
    def emitFeature(self):
        # 筛选关键字段并转换numpy类型
        selected_features = []
        for feature in self.features_dict:
            filtered = {
                'Src IP': feature.get('Source IP', ''),
                'Dst IP': feature.get('Destination IP', ''),
                'Src Port': int(feature.get('Source Port', 0)),
                'Dst Port': int(feature.get('Destination Port', 0)),
                'Protocol': self.protocol_mapping.get(int(feature.get('Protocol', 0)), 'Unknown'),
                'Fwd Pkts/s': int(feature.get('Fwd Packets/s', 0)),
                'Bwd Pkts/s': int(feature.get('Bwd Packets/s', 0)),
                'Total Length of Fwd Packets': int(feature.get('Total Length of Fwd Packets', 0)),
                'Total Length of Bwd Packets': int(feature.get('Total Length of Bwd Packets', 0)),
                'Flow Duration(ms)': float(feature.get('Flow Duration', 0)),
                'FIN Count': int(feature.get('FIN Flag Count', 0)),
                'SYN Count': int(feature.get('SYN Flag Count', 0)),
                'RST Count': int(feature.get('RST Flag Count', 0)),
                'ACK Count': int(feature.get('ACK Flag Count', 0)),
            }
            selected_features.append(filtered)

        # 发送精简后的特征数据
        if self.socketio:
            print("发送特征数据")
            self.socketio.emit('flow_feature',{'features': selected_features})

        return selected_features

    def start_extract(self,pcap_file=None):
        self.features_dict = []  # 清空特征字典列表
        if pcap_file !=None :
            self.file_path=pcap_file
        self.extractFeature()
        if pcap_file is None:
            self.emitFeature()

    def predictThreat(self):
        if not self.features_dict:
            raise ValueError("features_dict 为空. 请先extractFeature()")
            return None

        # Step 1: 构建 DataFrame
        df = pd.DataFrame(self.features_dict)

        # Step 2: 去除无意义列和 ID 列
        id_cols = ["Flow ID", "Source IP", "Destination IP","Timestamp"]
        id_info = df[id_cols].copy()
        df = df.drop(columns=id_cols, errors='ignore')

        # Step 3: 处理无穷值/空值
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)

        if df.empty:
            print("No valid data left after cleaning.")
            return []

        # Step 4: 标准化 + PCA
        X_scaled = self.scaler.transform(df)
        X_pca = self.pca.transform(X_scaled)

        # Step 5: 预测
        y_pred = self.model.predict(X_pca)

        # Step 6: 转换为原始标签
        labels = self.label_encoder.inverse_transform(y_pred)

        # Step 7: 构建结果
        results = []
        for i in range(len(labels)):
            threat_type = labels[i]
            results.append({
                "threat_type": self.threat_mapping.get(threat_type, threat_type),  # 获取中文名称，如果没有映射则使用原名
                "src_ip": id_info.iloc[i]["Source IP"] if "Source IP" in id_info.columns else "unknown",
                "dst_ip": id_info.iloc[i]["Destination IP"] if "Destination IP" in id_info.columns else "unknown",
                "severity": self.severity_mapping.get(threat_type, '未知'),  # 获取威胁等级
                "original_type": threat_type  # 保留原始类型名称
            })
        return results

    def parse_csv(self, file):
        df = pd.read_csv(file)
        print("CSV 文件的真实列名:", df.columns.tolist())
        df.columns = df.columns.str.strip()
        # 检查是否有重复列名
        duplicated_cols = df.columns[df.columns.duplicated()]
        if not duplicated_cols.empty:
            print(f"警告：发现重复列名 {duplicated_cols.tolist()}，已自动去重")

        # 确保列名唯一（通过添加后缀）
        df = df.loc[:, ~df.columns.duplicated(keep='first')]  # 保留第一个出现的列
        selected_columns = get_train_header()
        selected_columns.remove("Label")
        # 检查是否存在缺失列（调试用）
        missing_columns = [col for col in selected_columns if col not in df.columns]
        if missing_columns:
            print(f"警告：以下列仍然缺失: {missing_columns}")
        # 筛选 DataFrame，只保留指定列
        df_selected = df[selected_columns]
        # 将 DataFrame 转换为字典列表（每行一个字典）
        self.features_dict = df_selected.to_dict(orient='records')
        selected_features=[]
        for feature in self.features_dict:
            #print(row)
            filtered = {
                'Src IP': feature.get('Source IP', ''),
                'Dst IP': feature.get('Destination IP', ''),
                'Src Port': int(feature.get('Source Port', 0)),
                'Dst Port': int(feature.get('Destination Port', 0)),
                'Protocol': self.protocol_mapping.get(int(feature.get('Protocol', 0)), 'Unknown'),
                'Fwd Pkts/s': int(feature.get('Fwd Packets/s', 0)),
                'Bwd Pkts/s': int(feature.get('Bwd Packets/s', 0)),
                'Total Length of Fwd Packets': int(feature.get('Total Length of Fwd Packets', 0)),
                'Total Length of Bwd Packets': int(feature.get('Total Length of Bwd Packets', 0)),
                'Flow Duration(ms)': float(feature.get('Flow Duration', 0)),
                'FIN Count': int(feature.get('FIN Flag Count', 0)),
                'SYN Count': int(feature.get('SYN Flag Count', 0)),
                'RST Count': int(feature.get('RST Flag Count', 0)),
                'ACK Count': int(feature.get('ACK Flag Count', 0)),
            }
            selected_features.append(filtered)

        return selected_features
        

# 用于测试
# if __name__ == '__main__':
    # feature = ThreatFind("test2.pcap")
    # print(feature.extractFeature())
    # print(feature.predictThreat())