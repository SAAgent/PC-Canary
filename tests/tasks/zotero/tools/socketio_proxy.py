import socketio
import json
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
import time

# 配置日志
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('socketio_proxy')

# 配置
HTTP_PORT = 5001  # HTTP 中转服务器端口
SOCKETIO_SERVER = 'http://localhost:5000'  # 目标 Socket.IO 服务器

# 创建 Socket.IO 客户端
sio = socketio.Client()

# 处理 Socket.IO 事件
@sio.event
def connect():
    logger.info(f'已连接到 Socket.IO 服务器，SID: {sio.sid}')

@sio.event
def disconnect():
    logger.info('与 Socket.IO 服务器断开连接')

@sio.event
def connect_error(error):
    logger.error(f'Socket.IO 连接错误: {error}')

@sio.event
def confirmation(data):
    logger.info(f'收到确认事件: {data}')

# 确保 Socket.IO 连接
def ensure_socketio_connected():
    if not sio.connected:
        try:
            logger.info(f'正在连接到 Socket.IO 服务器 {SOCKETIO_SERVER}...')
            sio.connect(
                SOCKETIO_SERVER,
                transports=['websocket', 'polling'],
                wait_timeout=5
            )
            try:
                # 发送数据
                logger.info('正在发送app启动成功数据...')
                sio.emit('send', {'event_type': 'start_success'})
                logger.info('app启动成功数据发送成功')
            except Exception as e:
                logger.error(f'app启动成功发送数据失败: {e}')
                return False
            return True
        except Exception as e:
            logger.error(f'连接到 Socket.IO 服务器失败: {e}')
            return False
    return True

# HTTP 请求处理器
class ProxyHandler(BaseHTTPRequestHandler):
    def _send_response(self, status_code, data):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def do_OPTIONS(self):
        # 处理 CORS 预检请求
        self._send_response(200, {"status": "ok"})

    def do_GET(self):
        # 健康检查
        if self.path == '/health':
            self._send_response(200, {
                "status": "ok",
                "socketio_connected": sio.connected
            })
        else:
            self._send_response(404, {"error": "Not found"})

    def do_POST(self):
        # 处理事件转发
        if self.path == '/event':
            try:
                # 读取请求数据
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length).decode('utf-8')
                event_data = json.loads(post_data)
                
                logger.info(f'收到 HTTP 请求: {event_data}')
                
                # 确保连接到 Socket.IO 服务器
                if not ensure_socketio_connected():
                    self._send_response(503, {
                        "status": "error",
                        "message": "无法连接到 Socket.IO 服务器"
                    })
                    return
                
                # 转发事件到 Socket.IO 服务器
                response = {"status": "pending"}
                
                def ack_callback(*args):
                    nonlocal response
                    # 检查是否有参数传入
                    if args and len(args) > 0:
                        response = args[0] or {"status": "received"}
                    else:
                        response = {"status": "received", "note": "无确认数据"}
                    logger.info(f'收到 Socket.IO 确认: {response}')
                                
                logger.info(f'转发事件到 Socket.IO: {event_data}')
                sio.emit('send', event_data, callback=ack_callback)
                
                # 等待短暂时间以接收可能的同步响应
                time.sleep(0.1)
                
                self._send_response(200, {
                    "status": "success",
                    "message": "事件已转发",
                    "response": response
                })
                
            except json.JSONDecodeError:
                self._send_response(400, {
                    "status": "error",
                    "message": "无效的 JSON 数据"
                })
            except Exception as e:
                logger.error(f'处理请求时出错: {e}')
                self._send_response(500, {
                    "status": "error",
                    "message": f"内部服务器错误: {str(e)}"
                })
        else:
            self._send_response(404, {"error": "Not found"})

    # 简化日志输出
    def log_message(self, format, *args):
        if args and (args[0].startswith('2') or args[0].startswith('3')):
            return  # 不记录成功响应
        logger.info("%s - %s" % (self.client_address[0], format % args))

def run_http_server():
    server = HTTPServer(('0.0.0.0', HTTP_PORT), ProxyHandler)
    logger.info(f'HTTP 中转服务器运行在 http://0.0.0.0:{HTTP_PORT}')
    server.serve_forever()

if __name__ == "__main__":
    # 启动 HTTP 服务器
    http_thread = Thread(target=run_http_server)
    http_thread.daemon = True
    http_thread.start()
    
    try:
        # 初始连接尝试
        ensure_socketio_connected()
        
        # 保持主线程运行
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("正在关闭服务...")
        if sio.connected:
            sio.disconnect()