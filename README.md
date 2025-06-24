## 项目概述
已在release中上传打包好的exe，在已安装好npcap下可直接运行
### 背景

网络入侵检测是网络安全的核心技术，用于检测恶意行为如未授权访问、恶意软件攻击和拒绝服务攻击。本系统采用随机森林模型进行入侵检测。

### 核心功能

1.  实时数据包抓取与协议分析
    
2.  流量特征提取（从pcap文件）
    
3.  基于随机森林模型的威胁检测
    1.  模型训练代码也在其中
    
4.  可视化分析界面
    

## 技术栈

### 前端

*   Bootstrap 5 (界面框架)
    
*   jQuery (DOM操作)
    
*   Plotly v5.3.1 (数据可视化)
    

### 后端

*   Flask v2.2.5 (核心Web框架)
    
*   Pywebview (桌面应用转换)
    
*   Pyinstaller (打包)
    

### 数据处理

*   pandas v2.2.3 (数据操作)
    
*   numpy v2.2.6 (数值计算)
    
*   Scikit-learn 1.6.1 (特征预处理和降维)
    

### 其他

*   scapy v2.4.5 (数据包操作)
    
*   Joblib (模型持久化)
    
*   RandomForestClassifier (威胁检测模型)
    

## 安装部署


### 必需组件
下载npcap: https://npcap.com/#download

### 运行方式
1. 直接运行: 双击ids.exe
2. 源码运行:   
   - 安装依赖: 
```bash
pip install \-r requirements.txt
# 激活虚拟环境: 
venv\\Scripts\\activate

3. 运行: 
```bash
   python app.py #(浏览器模式) 或
   python main.py # (桌面模式)
```
4. 打包:
```bash
pyinstaller main.spec
```

## 系统架构

```unix
IDS/
├── app/                          # 主应用模块
│   ├── app.py                    # Flask入口
│   ├── main.py                   # 桌面程序入口
│   ├── model/                    # 机器学习模型
│   ├── modules/                  # 功能模块
│   │   ├── pocket\_detection/     # 数据包捕获
│   │   └── threat\_find/          # 威胁检测
│   ├── templates/                # 前端页面
│   └── 测试用例/                 # 测试数据
├── data/                         # 运行时数据
├── requirements.txt              # 依赖库
└── venv/                         # 虚拟环境
```
## 核心模块设计

### 1\. 数据包抓取与分析

*   实时监听网络端口
    
*   协议分析（IP/TCP/UDP/ICMP/HTTP）
    
*   数据可视化（协议分布饼图）
    
*   数据包存储（JSON和PCAP格式）
    


### 2\. 流量特征提取

提取86维网络流量特征，包括：

*   流基本信息（IP/端口/协议）
    
*   数据包统计特征
    
*   流速相关特征
    
*   TCP标志特征
    
*   流活动特征
    

### 3\. 威胁检测模型

*   数据集：CIC-IDS2017 (1.13GB网络流量数据:https://www.unb.ca/cic/datasets/ids-2017.html)
    
*   预处理：标准化+欠采样+PCA降维
    
*   模型：网格搜索优化的随机森林
    
*   检测类型：12类威胁（包括DDoS、PortScan等）

*   准确率：92.7%（测试数据集）
    

## 使用说明

### 网络监控

1.  查看实时协议分布
    
2.  检查捕获的数据包
    
3.  使用筛选器（IP/端口）
    
4.  分析单个数据包（协议详情+十六进制视图）
    

### 威胁检测

1.  **文件分析模式**：
    
    *   上传PCAP或CSV文件
        
    *   提取流量特征
        
    *   执行威胁检测
        
2.  **实时检测模式**：
    
    *   启动网络扫描
        
    *   停止扫描后自动分析
        
    *   查看威胁分类结果
        
## 小组成员
- ![KK-Ann](https://github.com/KK-Ann)
- ![evenhu9](https://github.com/evenhu9)
