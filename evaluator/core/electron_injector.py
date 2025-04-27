from typing import List, Dict, Any, Optional, Callable
import os
import logging
import eventlet
import socketio
from multiprocessing import Process, Manager
import threading
import time
import signal
import subprocess

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
            for p in shared_dict['scripts']:
                with open(p, 'r') as f:
                    sio.emit('inject', f.read(), to=sid)
            # 更新共享的session_id列表
            shared_dict['target_session_id'].append(sid)
            shared_dict['logger'].info(f"客户端app连接到服务器: {sid}")
            shared_dict['logger'].info(f"当前app: {shared_dict['target_session_id']}")

        @sio.event
        def send(sid, message):
            # 将消息放入队列，由主进程处理
            shared_dict['logger'].info(f"app向评估器发送消息")
            shared_dict['msg_from_app'].append({
                'type': 'message',
                'content': message
            })

        def process_message_queue():
            # 单次处理消息队列的函数
            try:
                if shared_dict['msg_from_evaluator']:
                    for msg in shared_dict['msg_from_evaluator']:
                        if msg['type'] == 'inject' and 'sid' in msg and 'content' in msg:
                            sio.emit('inject', msg['content'], to=msg['sid'])
                        elif msg['type'] == 'evaluate' and 'sid' in msg:
                            sio.emit('evaluate', to=msg['sid'])
                        else:
                            shared_dict['logger'].warning(f"无效的消息格式或缺少sid: {msg}")
                    shared_dict['msg_from_evaluator'][:] = []
            except Exception as e:
                shared_dict['logger'].error(f"处理消息错误: {str(e)}")
            # 调度下一次执行
            eventlet.spawn_after(0.5, process_message_queue)

        # 启动消息处理线程
        try:
            eventlet.spawn_after(1, process_message_queue)
            shared_dict['logger'].info("服务器启动消息处理成功")
        except Exception as e:
            shared_dict['logger'].error(f"服务器启动消息处理报错: {str(e)}")

        try:
            eventlet.wsgi.server(eventlet.listen(('', 5000)), app, log_output=False)
        except Exception as e:
            shared_dict['logger'].error(f"服务器运行错误: {str(e)}")


    def __init__(self, app_path: str = None, args: List[str] = None, logger: Optional[logging.Logger] = None, evaluate_on_completion: bool = False):
        # 创建进程管理器
        self.manager = Manager()
        self.app_path = app_path
        self.args = args
        # 创建共享字典
        self.shared_dict = self.manager.dict({
            'scripts': self.manager.list(),
            'loaded_scripts': self.manager.list(),
            'target_session_id': self.manager.list(),
            'msg_from_evaluator': self.manager.list(),
            'msg_from_app': self.manager.list(),
            "evaluate_on_completion": evaluate_on_completion,
            'logger': logger
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
        self.logger = logger
        self.app_connect = False
        self.app_process = None
        self.evaluate_on_completion = evaluate_on_completion
        self.triggered_evaluate = False

    def trigger_evaluate_on_completion(self):
        """
        在任务操作完成时触发评估, 预留的接口需要保证是evaluate
        """
        # 在任务操作完毕时触发任务完成的评估
        self.logger.info("在任务操作完毕时触发评估")
        for sid in self.shared_dict['target_session_id']:
            self.shared_dict['msg_from_evaluator'].append({
                'type': 'evaluate',
                'sid': sid
            })
        # 等待评估完毕
        max_wait_time = 10
        start_wait = time.time()
        while time.time() - start_wait < max_wait_time:
            if self.triggered_evaluate:
                self.logger.info("任务评估完成")
                break
            time.sleep(0.5)

    def _handle_messages(self):
        # 处理从子进程发来的消息
        while self.message_handle_running:
            try:
                for message in self.shared_dict['msg_from_app']:
                    if message['type'] == 'message':
                        self.shared_dict['logger'].info(f"handle_messager收到消息")
                        if message["content"].get("event_type") == "start_success":
                            # 应用的渲染进程或者插件启动成功
                            self.app_connect = True
                            self.shared_dict['logger'].info("应用成功连接到socket服务")
                        elif self.on_message:
                            self.on_message(message['content'], None)
                            if message["content"].get("event_type") == "evaluate_on_completion":
                                self.triggered_evaluate = True
                self.shared_dict['msg_from_app'] = self.manager.list()
            except BrokenPipeError:
                break
            except Exception as e:
                self.shared_dict['logger'].error(f"处理消息错误: {str(e)}")
            time.sleep(0.5)

    def add_script(self, task_path: str) -> None:
        hooker_path = os.path.join(task_path, "hooker.js")
        if os.path.exists(hooker_path):
            self.shared_dict['scripts'].append(hooker_path)
            self.shared_dict['logger'].info(f"添加钩子脚本: {hooker_path}")
        else:
            self.shared_dict['logger'].error(f"脚本文件不存在: {hooker_path}")
    
    def load_scripts(self, eval_handler: Callable[[Dict[str, Any], Any], None]) -> bool:
        self.on_message = eval_handler
        if not self.shared_dict['scripts']:
            self.shared_dict['logger'].warning("没有脚本可加载")
            return False
    
        if not self.shared_dict['target_session_id']:
            self.shared_dict['logger'].warning(f"目标APP无法连接, {self.shared_dict['target_session_id']}")
            return False

        try:
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
            if self.evaluate_on_completion:
                self.trigger_evaluate_on_completion()

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

    def start_app(self) -> bool:
        #  如果提供了应用路径，则启动应用
        if self.app_path and os.path.exists(self.app_path):
            self.app_path = self.app_path
            if self.args is None:
                self.args = []
        
            # 构建完整的命令行
            cmd = [self.app_path] + self.args
        
            try:
                # 启动应用进程
                self.logger.info(f"正在启动应用: {self.app_path}")
                self.app_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )

                self.logger.info(f"应用启动成功，进程ID: {self.app_process.pid}")

                # 等待应用窗口加载完成
                self.logger.info("等待应用窗口加载完成...")

                # Linux系统：使用xwininfo命令检测窗口变化
                try:
                    # 获取启动前窗口列表
                    windows_before = subprocess.run(["xwininfo", "-root", "-tree"], 
                                                stdout=subprocess.PIPE, 
                                                text=True).stdout.count('\n')
                    self.logger.info(f"启动前窗口行数: {windows_before}")

                    # 等待新窗口出现
                    max_wait_time = 30  # 最大等待30秒
                    start_wait = time.time()
                    window_detected = False

                    while time.time() - start_wait < max_wait_time:
                        windows_current = subprocess.run(["xwininfo", "-root", "-tree"], 
                                                    stdout=subprocess.PIPE, 
                                                    text=True).stdout.count('\n')
                        if windows_current > windows_before:
                            window_detected = True
                            self.logger.info(f"检测到新窗口，当前窗口行数: {windows_current}")
                            # 额外等待2秒确保窗口内容加载完成
                            time.sleep(2)
                            break
                        time.sleep(0.5)

                    if not window_detected:
                        self.logger.warning("未检测到新窗口出现，使用默认等待时间")
                        time.sleep(5)
                except Exception as window_error:
                    self.logger.warning(f"窗口检测出错: {str(window_error)}，使用默认等待时间")
                    time.sleep(5)
                
                # 等待渲染进程或者插件启动
                try:
                    max_wait_time = 600
                    start_wait = time.time()
                    while time.time() - start_wait < max_wait_time:
                        if self.app_connect:
                            self.logger.info("检测到应用成功连接到socket服务")
                            break
                        time.sleep(0.5)
                    if not self.app_connect:
                        self.logger.warning("没有检测到应用连接socket服务")
                except Exception as e:
                    self.logger.error(f"应用socket连接失败: {str(e)}")
            except Exception as e:
                self.logger.error(f"应用启动失败: {str(e)}")
        elif self.app_path:
            self.logger.error(f"应用路径不存在: {self.app_path}")

        self.app_started = True
        return True
    
    def stop_app(self) -> None:
        # 停止应用进程
        if hasattr(self, 'app_process') and self.app_process:
            try:
                self.logger.info(f"尝试优雅地终止应用进程 (PID: {self.app_process.pid})")

                # 发送SIGTERM信号，通知应用准备关闭
                self.app_process.send_signal(signal.SIGTERM)
                self.logger.info("已发送SIGTERM信号，等待应用响应...")

                # 等待应用自行关闭
                try:
                    self.app_process.wait(timeout=10)  # 等待10秒
                    self.logger.info("应用进程已自行关闭")
                except subprocess.TimeoutExpired:
                    self.logger.warning("应用未在预期时间内关闭，尝试使用terminate()")
                    self.app_process.terminate()
                    try:
                        self.app_process.wait(timeout=5)
                        self.logger.info("应用进程已通过terminate()正常终止")
                    except subprocess.TimeoutExpired:
                        self.logger.warning("应用未能通过terminate()关闭，尝试使用kill()")
                        self.app_process.kill()
                        self.logger.info("应用进程已通过kill()强制终止")
            except Exception as e:
                self.logger.error(f"终止应用进程时出错: {str(e)}")
