"""
代码执行环境控制器 - 为LLM提供一个可执行的代码环境
"""

import os
import time
import re
import json
import sys
import pyautogui
from PIL import ImageGrab


class CodeExecutionController:
    """
    代码执行环境 - 为LLM提供一个可执行的Python环境
    
    该环境预先配置了常用的GUI自动化库和辅助函数，
    允许直接执行LLM生成的代码块，并支持特殊命令。
    """
    
    def __init__(self):
        """初始化执行环境"""
        # 设置PyAutoGUI安全设置
        pyautogui.FAILSAFE = True  # 将鼠标移动到左上角将触发异常
        pyautogui.PAUSE = 0.5  # 操作之间的默认暂停时间
        
        # 任务状态标志
        self.task_completed = False
        self.task_failed = False
        
        # 预定义的特殊命令
        self.special_commands = {
            'WAIT': self._cmd_wait,
            'DONE': self._cmd_done,
            'FAIL': self._cmd_fail
        }
        
        # 上下文变量，用于跟踪执行状态
        self.context = {}
    
    def _cmd_wait(self, seconds=3):
        """等待命令 - 暂停执行一段时间"""
        print(f"执行WAIT命令：暂停{seconds}秒...")
        time.sleep(seconds)
        return True
    
    def _cmd_done(self):
        """完成命令 - 标记任务已完成"""
        print("执行DONE命令：任务已完成")
        self.task_completed = True
        return True
    
    def _cmd_fail(self, reason="未指定原因"):
        """失败命令 - 标记任务失败"""
        print(f"执行FAIL命令：任务失败 - {reason}")
        self.task_failed = True
        return False
    
    def get_screenshot(self):
        """获取屏幕截图"""
        screenshot = ImageGrab.grab()
        return screenshot
    
    def move_to(self, x, y):
        """移动鼠标到指定位置"""
        pyautogui.moveTo(x, y)
    
    def execute(self, code_block):
        """
        执行代码块
        
        Args:
            code_block: LLM生成的代码块
            
        Returns:
            tuple: (执行结果, 特殊状态)
                - 执行结果: 布尔值，表示执行是否成功
                - 特殊状态: None, "done" 或 "fail"
        """
        if not code_block or code_block.strip() == "":
            return True, None
            
        # 预处理代码，解析特殊命令
        code_lines = code_block.strip().split('\n')
        processed_lines = []
        special_status = None
        
        # 首先检查是否整个代码块就是一个特殊命令
        if code_block.strip() in self.special_commands:
            command = code_block.strip()
            result = self.special_commands[command]()
            if command == 'DONE':
                special_status = "done"
            elif command == 'FAIL':
                special_status = "fail"
            return result, special_status
        
        # 处理代码中的特殊命令
        i = 0
        while i < len(code_lines):
            line = code_lines[i].strip()
            
            # 检查是否为特殊命令
            if line in self.special_commands:
                if line == 'WAIT':
                    # 查找下一行是否指定了等待时间
                    if i+1 < len(code_lines) and re.match(r'^\d+$', code_lines[i+1].strip()):
                        seconds = int(code_lines[i+1].strip())
                        self._cmd_wait(seconds)
                        i += 2  # 跳过时间参数行
                        continue
                    else:
                        self._cmd_wait()  # 使用默认时间
                elif line == 'DONE':
                    self._cmd_done()
                    special_status = "done"
                    # 不需要执行后续代码
                    break
                elif line == 'FAIL':
                    # 检查是否有失败原因
                    if i+1 < len(code_lines) and not code_lines[i+1].strip() in self.special_commands:
                        reason = code_lines[i+1].strip()
                        self._cmd_fail(reason)
                        i += 2  # 跳过原因行
                        continue
                    else:
                        self._cmd_fail()
                    special_status = "fail"
                    # 不需要执行后续代码
                    break
            else:
                # 普通代码行，保留
                processed_lines.append(code_lines[i])
            i += 1
        
        # 如果全部是特殊命令，则无需执行实际代码
        if not processed_lines:
            return True, special_status
        
        # 构建实际执行的代码
        executable_code = '\n'.join(processed_lines)
        
        # 准备执行环境
        exec_globals = {
            '__builtins__': __builtins__,
            'pyautogui': pyautogui,
            'time': time,
            'os': os,
            'sys': sys,
            're': re,
            'json': json,
            'PIL': __import__('PIL'),
            'ImageGrab': ImageGrab,
        }
        
        # 执行代码
        try:
            print("执行代码...")
            exec(executable_code, exec_globals, self.context)
            return True, special_status
        except Exception as e:
            print(f"执行代码出错: {str(e)}")
            import traceback
            traceback.print_exc()
            return False, special_status