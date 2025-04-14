from typing import List, Dict, Any, Optional, Callable
import os
import logging
import eventlet
import socketio
import multiprocessing
from multiprocessing import Process, Manager
from queue import Empty
import threading
import time

class ElectronInjector:
    """
    基于electron开发的app的钩子管理器, 负责加载和管理注入脚本
    """
    def start_server(self, shared_dict):
        # 子进程的服务器函数
        sio = socketio.Server()
        app = socketio.WSGIApp(sio)

        @sio.event
        def connect(sid, _):
            for p in shared_dict['loaded_scripts']:
                with open(p, 'r') as f:
                    sio.emit('inject', f.read(), to=sid)
            # 更新共享的session_id列表
            shared_dict['target_session_id'].append(sid)
            shared_dict['logger'].info(f"客户端app连接到服务器: {sid}")
            shared_dict['logger'].info(f"当前app: {shared_dict['target_session_id']}")

        @sio.event
        def send(sid, message):
            # 将消息放入队列，由主进程处理
            shared_dict['logger'].info(f"app发送消息: {message}")
            shared_dict['msg_from_app'].append({
                'type': 'message',
                'content': message
            })

        # 添加消息处理循环
        def process_message_queue():
            while True:
                try:
                    for msg in shared_dict['msg_from_evaluator']:
                        if msg['type'] == 'inject':
                            sio.emit('inject', msg['content'], to=msg['sid'])
                        elif msg['type'] == 'restore':
                            sio.emit('restore', to=msg['sid'])
                    shared_dict['msg_from_evaluator'][:] = []
                except Exception as e:
                    shared_dict['logger'].error(f"处理消息错误: {str(e)}")
                time.sleep(1)

        # 启动消息处理线程
        message_thread = threading.Thread(target=process_message_queue)
        message_thread.daemon = True
        message_thread.start()

        try:
            eventlet.wsgi.server(eventlet.listen(('', 5000)), app, log_output=True)
        except Exception as e:
            shared_dict['logger'].error(f"服务器运行错误: {str(e)}")


    def __init__(self, logger: Optional[logging.Logger] = None):
        # 创建进程管理器
        self.manager = Manager()
        # 创建共享字典
        self.shared_dict = self.manager.dict({
            'scripts': self.manager.list(),
            'loaded_scripts': self.manager.list(),
            'target_session_id': self.manager.list(),
            'msg_from_evaluator': self.manager.list(),
            'msg_from_app': self.manager.list(),
            'logger': logger,
        })

        self.on_message = None
        
        # 创建并启动服务器进程
        self.server = Process(
            target=self.start_server,
            args=[self.shared_dict]
        )
        self.server.start()
        
        # 启动消息处理线程
        self.message_handler = threading.Thread(target=self._handle_messages)
        self.message_handle_running = True
        self.message_handler.start()

    def _handle_messages(self):
        # 处理从子进程发来的消息
        while self.message_handle_running:
            try:
                for message in self.shared_dict['msg_from_app']:
                    if message['type'] == 'message' and self.on_message:
                        self.shared_dict['logger'].info(f"handle_messager poll到消息: {message}")
                        self.on_message(message['content'], None)
                self.shared_dict['msg_from_app'] = self.manager.list()
            except Exception as e:
                self.shared_dict['logger'].error(f"处理消息错误: {str(e)}")
            time.sleep(1)

    def add_script(self, task_path: str) -> None:
        hooker_path = os.path.join(task_path, "hooker.js")
        if os.path.exists(hooker_path):
            self.shared_dict['scripts'].append(hooker_path)
            self.shared_dict['logger'].info(f"添加钩子脚本: {hooker_path}")
        else:
            self.shared_dict['logger'].error(f"脚本文件不存在: {hooker_path}")
    
    def load_scripts(self, _: str, eval_handler: Callable[[Dict[str, Any], Any], None]) -> bool:
        if not self.shared_dict['scripts']:
            self.shared_dict['logger'].warning("没有脚本可加载")
            return False
    
        if not self.shared_dict['target_session_id']:
            self.shared_dict['logger'].warning(f"目标APP无法连接, {self.shared_dict['target_session_id']}")
            return False

        try:
            self.on_message = eval_handler
            success = False
            
            for script_path in self.shared_dict['scripts']:
                try:
                    with open(script_path, 'r') as f:
                        script_content = f.read()
                    
                    # 向所有已连接的客户端发送注入命令
                    for sid in self.shared_dict['target_session_id']:
                        self.shared_dict['msg_from_evaluator'].append({
                            'type': 'inject',
                            'sid': sid,
                            'content': script_content
                        })
                    
                    self.shared_dict['loaded_scripts'].append(script_path)
                    success = True
                    self.shared_dict['logger'].info(f"加载脚本成功: {script_path}, {self.shared_dict['target_session_id']}")
                except Exception as e:
                    self.shared_dict['logger'].error(f"加载脚本失败 {script_path}: {str(e)}")
            return success
        except Exception as e:
            self.shared_dict['logger'].error(f"连接到进程失败: {str(e)}")
            return False
        
    def unload_scripts(self) -> None:
        try:
            for sid in self.shared_dict['target_session_id']:
                self.shared_dict['msg_from_evaluator'].append({
                    'type': "restore",
                    'sid': sid,
                })
            self.shared_dict['loaded_scripts'] = self.manager.list()
            self.shared_dict['target_session_id'] = self.manager.list()
            
            self.message_handle_running = False
            # 终止服务器进程
            if self.server.is_alive():
                self.server.terminate()
                self.server.join(timeout=5)
            
            # 清理管理器
            self.manager.shutdown()
            
        except Exception as e:
            self.shared_dict['logger'].error(f"卸载脚本失败: {str(e)}")
