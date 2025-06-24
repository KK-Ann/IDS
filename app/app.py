#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import threading
import logging
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO

# 导入自定义模块
from modules.pocket_detection.detector import TrafficDetector as PocketDetector
from modules.threat_find.ThreatFind import ThreatFind
import os
import sys

# 创建 data 文件夹（如果不存在）
os.makedirs('data', exist_ok=True)
# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('data/ids_system.log')
    ]
)
logger = logging.getLogger(__name__)

# 初始化Flask应用
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
socketio = SocketIO(app)

# 创建数据目录
os.makedirs('data', exist_ok=True)

# 初始化系统模块
def resource_path(relative_path):
    """获取 PyInstaller 打包后资源路径"""
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

model_path = resource_path("model/randomforest_model.pkl")
pipeline_path = resource_path("model/preprocessing_pipeline.pkl")
pocket_detector = PocketDetector()
flow_feature = ThreatFind(None, socketio, model_path, pipeline_path)

# 管理系统状态
system_status = {
    'is_running': False,
    'start_time': None,
    'processed_packets': 0,
    'detected_threats': 0,
    'blocked_attacks': 0
}


# 路由定义
@app.route('/')
def index():
    return render_template('index.html')



@app.route('/network_monitor')
def network():
    return render_template('network_monitor.html')
@app.route('/intrusion_detection')
def intrusion():
    return render_template('intrusion_detection.html')

@app.route('/logs')
def logs():
    return render_template('logs.html')



# API路由
@app.route('/api/status')
def get_status():
    return jsonify(system_status)


@app.route('/api/start', methods=['POST'])
def start_system():
    if not system_status['is_running']:
        system_status['is_running'] = True
        system_status['start_time'] = time.time()

        # 启动各个模块
        threading.Thread(target=pocket_detector.start_capture).start()
        # threading.Thread(target=flow_feature.start_extract).start()
        logger.info("系统已启动")
        return jsonify({'success': True, 'message': '系统已启动'})

    return jsonify({'success': False, 'message': '系统已在运行中'})


@app.route('/api/stop', methods=['POST'])
def stop_system():
    if system_status['is_running']:
        system_status['is_running'] = False

        # 停止各个模块
        pocket_detector.stop_capture()
        files = pocket_detector.get_pcapfiles()
        # print("打印文件",files)
        if len(files) == 0:
            return jsonify({'success': True,'warning':True,'message':'还未捕获到足够的包，无法进行威胁分析'})
        flow_feature.start_extract(files)
        logger.info("系统已停止")
        return jsonify({'success': True,'warning':False, 'message': '系统已停止'})

    return jsonify({'success': False, 'warning':False, 'message': '系统未运行'})
# 捕获数据包
@app.route('/api/protocol_stats')
def get_protocol_stats():
    return jsonify(pocket_detector.get_traffic_stats())

@app.route('/api/packets')
def get_packets():
    return jsonify(pocket_detector.get_recent_traffic(1000))

@app.route('/api/detect_protocols', methods=['POST'])
def detect_protocols():
    if not request.json or 'raw_data' not in request.json:
        return jsonify({'error': '缺少raw_data参数'}), 400
        
    result = pocket_detector.analyze_packet(request.json['raw_data'])
    
    if not result:
        return jsonify({'error': '数据包解析失败'}), 400
        
    return jsonify(result)
# 流量统计和威胁
@app.route('/api/flow_features')
def get_flow_features():
   # print("get发特征数据")
    return jsonify({"features":flow_feature.getFeatures()})

@app.route('/api/analyze_file', methods=['POST'])
def analyze_file():
    try:
        # 从请求表单中获取数据
        file_path = request.form.get('file_path')
        # print(file_path)
        # 检查必填字段是否存在
        if not file_path :
            return jsonify({
                "success": False,
                "message": "没有文件路径"
            })
        elif not os.path.isfile(file_path):
            return jsonify({
                "success": False,
                "message": "文件不存在"})
        elif file_path.endswith('.pcap'):
            flow_feature.extractFeature(file_path)
            return jsonify({"success": True,"data":{"features":flow_feature.getFeatures()}})
        elif file_path.endswith('.csv'):
            # 使用pandas解析CSV文件
            return jsonify({"success": True,"data":{"features": flow_feature.parse_csv(file_path)}})
        else:
            return jsonify(success=False, message="不支持的文件格式")
    except Exception as e:
        return jsonify(success=False, message=f"文件解析失败：{str(e)}")

@ app.route("/api/start_threatdetection", methods=['GET'])
def start_threatdetection():
    try:
        ret=flow_feature.predictThreat()
        if  ret is None:
            return jsonify(success=False,message="没有流量可供检测")
        else:
            return jsonify({"success": True,"data":{"threats":flow_feature.predictThreat()}})
    except Exception as e:
        return jsonify(success=False, message=f"威胁识别失败：{str(e)}")

# Socket.IO 事件
@socketio.on('connect')
def handle_connect():
    logger.info(f"客户端已连接: {request.sid}")


@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f"客户端已断开连接: {request.sid}")




# 主函数
if __name__ == '__main__':
    try:
        logger.info("网络入侵检测系统启动中...")
        socketio.run(app, host='127.0.0.1', port=8080, debug=True) # 打包/运行main.py时把debug去掉！！！
    except Exception as e:
        logger.error(f"系统启动失败: {str(e)}")
