from typing import List, Dict, Any, Optional, Callable
import os
import frida
import logging
import time
import signal
import subprocess


class HookManager:
    """
    钩子管理器，负责加载和管理Frida脚本
    """
    
    def __init__(self, app_path: str = None, app_working_cwd: Optional[str] = None,
                 args: List[str] = None, logger: Optional[logging.Logger] = None,
                 evaluate_on_completion: bool = False):
        """
        初始化钩子管理器
        
        Args:
            logger: 日志记录器，如果为None则使用默认记录器
        """
        self.scripts = []  # 脚本路径列表
        self.app_path = app_path  # 应用路径
        self.app_working_cwd = app_working_cwd if app_working_cwd else os.getcwd()
        self.frida_session = None  # Frida会话
        self.loaded_scripts = []  # 已加载的脚本对象
        self.message_handler = None  # 消息处理函数
        self.logger = logger
        self.args = args
        self.app_process = None
        self.evaluate_on_completion = evaluate_on_completion
        
        
    def add_script(self, hooker_path: str, dep_script: str) -> None:
        """
        添加钩子脚本
        
        Args:
            task_id: 脚本路径
        """
        if os.path.exists(hooker_path):
            self.scripts.append((hooker_path,dep_script))
            self.logger.info(f"添加钩子脚本: {hooker_path}")
        else:
            self.logger.error(f"脚本文件不存在: {hooker_path}")
    
    
    def load_scripts(self, eval_handler: Callable[[Dict[str, Any], Any], None]) -> bool:
        """
        加载脚本到目标进程
        
        Args:
            eval_handler: 任务的事件处理器
            
        Returns:
            bool: 加载是否成功
        """
        if not self.scripts:
            self.logger.warning("没有脚本可加载")
            return False
        
        try:
            # 连接到目标进程
            self.logger.info(f"连接到进程: {self.app_process.pid}")
            self.frida_session = frida.attach(self.app_process.pid)
            
            # 加载所有脚本
            for (script_path,dep_script) in self.scripts:
                try:
                    with open(script_path, 'r') as f:
                        script_content = "".join([dep_script,f.read()])
                    
                    script = self.frida_session.create_script(script_content)
                    script.on('message', eval_handler)
                    script.load()
                    
                    self.loaded_scripts.append(script)
                    self.logger.info(f"加载脚本成功: {script_path}")
                except Exception as e:
                    self.logger.error(f"加载脚本失败 {script_path}: {str(e)}")
            
            return len(self.loaded_scripts) > 0
        
        except frida.ProcessNotFoundError:
            self.logger.error(f"未找到进程: {self.app_process.pid}")
            return False
        except Exception as e:
            self.logger.error(f"连接到进程失败: {str(e)}")
            return False
    
    def unload_scripts(self) -> None:
        """
        卸载所有脚本
        """
        try:
            for script in self.loaded_scripts:
                script.unload()
            
            self.loaded_scripts = []
            
            if self.frida_session:
                self.frida_session.detach()
                self.frida_session = None
            
            self.logger.info("脚本卸载完成")
        except Exception as e:
            self.logger.error(f"卸载脚本失败: {str(e)}")
            
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
                    cwd=self.app_working_cwd,
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
            except Exception as e:
                self.logger.error(f"应用启动失败: {str(e)}")
        else:
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

    def trigger_evaluate_on_completion(self):
        pass
