import webview
from app import app, socketio
import threading
import logging

def start_server():
    """启动Flask服务器"""
    socketio.run(app, host='127.0.0.1', port=8080)

if __name__ == '__main__':
    # 配置日志
    logging.basicConfig(level=logging.INFO)
    
    # 启动Flask服务器线程
    server_thread = threading.Thread(target=start_server)
    server_thread.daemon = True
    server_thread.start()
    
    # 创建PyWebView窗口,并启动
    webview.create_window(
        "网络入侵检测系统", 
        "http://127.0.0.1:8080",
        width=1425,
        height=800,
        resizable=True
    )
    
    # 启动PyWebView
    webview.start()