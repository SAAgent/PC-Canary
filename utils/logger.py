#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
高级日志系统 - 记录代码执行、保存截图并标记操作位置
"""

import os
import re
import json
import time
import uuid
import datetime
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

class AgentLogger:
    """
    Agent执行日志管理系统
    支持记录代码执行、保存截图并标记操作位置
    """
    
    def __init__(self, base_log_dir="logs", session_id=None):
        """
        初始化日志系统
        
        Args:
            base_log_dir: 基础日志目录
            session_id: 会话ID（如未提供则自动生成）
        """
        self.base_log_dir = base_log_dir
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_id = session_id or f"{self.timestamp}_{uuid.uuid4().hex[:8]}"
        
        # 创建会话目录结构
        self.session_dir = os.path.join(self.base_log_dir, self.session_id)
        self.screenshots_dir = os.path.join(self.session_dir, "screenshots")
        self.actions_dir = os.path.join(self.session_dir, "actions")
        self.metadata_dir = os.path.join(self.session_dir, "metadata")
        
        # 确保目录存在
        os.makedirs(self.session_dir, exist_ok=True)
        os.makedirs(self.screenshots_dir, exist_ok=True)
        os.makedirs(self.actions_dir, exist_ok=True)
        os.makedirs(self.metadata_dir, exist_ok=True)
        
        # 初始化会话日志
        self.session_log = {
            "session_id": self.session_id,
            "start_time": time.time(),
            "steps": [],
            "status": "running"
        }
        self._save_session_metadata()
        
        # 当前步骤的索引
        self.current_step = 0
        
        # 字体设置 (用于标记截图)
        try:
            # 尝试加载系统字体
            # self.font = ImageFont.truetype("Arial", 20)  # 在Windows上常见的字体
            # 不同系统上的字体路径可能不同，提供几个常见选项
            font_paths = [
                "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",  # Debian/Ubuntu
                "/usr/share/fonts/TTF/DejaVuSans.ttf",              # Arch Linux
                "/System/Library/Fonts/Helvetica.ttc",              # macOS
                "C:\\Windows\\Fonts\\arial.ttf"                     # Windows
            ]
            
            for font_path in font_paths:
                if os.path.exists(font_path):
                    self.font = ImageFont.truetype(font_path, 20)
                    break
            else:
                # 如果没有找到任何字体，使用默认字体
                self.font = ImageFont.load_default()
        except Exception as e:
            print(f"无法加载字体，使用默认字体: {e}")
            self.font = ImageFont.load_default()
    
    def _save_session_metadata(self):
        """保存会话元数据"""
        with open(os.path.join(self.metadata_dir, "session.json"), 'w', encoding='utf-8') as f:
            json.dump(self.session_log, f, ensure_ascii=False, indent=2)
    
    def start_step(self, instruction=None):
        """
        开始新的步骤记录
        
        Args:
            instruction: 当前步骤的指令
        
        Returns:
            当前步骤索引
        """
        self.current_step += 1
        
        # 创建步骤记录
        step_data = {
            "step_id": self.current_step,
            "start_time": time.time(),
            "instruction": instruction,
            "screenshot": None,
            "action_code": None,
            "thought": None,
            "execution_result": None,
            "marked_screenshot": None
        }
        
        self.session_log["steps"].append(step_data)
        self._save_session_metadata()
        
        return self.current_step
    
    def log_screenshot(self, screenshot, step_id=None):
        """
        记录屏幕截图
        
        Args:
            screenshot: PIL.Image对象或图像路径
            step_id: 步骤ID (如果为None则使用当前步骤)
        
        Returns:
            保存的截图路径
        """
        step_id = step_id or self.current_step
        
        # 确保screenshot是PIL.Image对象
        if isinstance(screenshot, str):
            screenshot = Image.open(screenshot)
        
        # 保存截图
        screenshot_filename = f"step_{step_id}_screenshot_{int(time.time())}.png"
        screenshot_path = os.path.join(self.screenshots_dir, screenshot_filename)
        screenshot.save(screenshot_path)
        
        # 更新步骤数据
        for step in self.session_log["steps"]:
            if step["step_id"] == step_id:
                step["screenshot"] = screenshot_path
                break
        
        self._save_session_metadata()
        return screenshot_path
    
    def log_action(self, action_code, thought=None, step_id=None):
        """
        记录代码执行动作
        
        Args:
            action_code: 执行的代码
            thought: 思考过程
            step_id: 步骤ID (如果为None则使用当前步骤)
        """
        step_id = step_id or self.current_step
        
        # 保存代码到文件
        action_filename = f"step_{step_id}_action_{int(time.time())}.py"
        action_path = os.path.join(self.actions_dir, action_filename)
        
        with open(action_path, 'w', encoding='utf-8') as f:
            f.write(action_code)
        
        # 更新步骤数据
        for step in self.session_log["steps"]:
            if step["step_id"] == step_id:
                step["action_code"] = action_path
                step["thought"] = thought
                break
        
        self._save_session_metadata()
        return action_path
    
    def log_execution_result(self, result, step_id=None):
        """
        记录代码执行结果
        
        Args:
            result: 执行结果
            step_id: 步骤ID (如果为None则使用当前步骤)
        """
        step_id = step_id or self.current_step
        
        # 更新步骤数据
        for step in self.session_log["steps"]:
            if step["step_id"] == step_id:
                step["execution_result"] = result
                break
        
        self._save_session_metadata()
    
    def _extract_click_coordinates(self, code):
        """
        从代码中提取点击坐标
        
        Args:
            code: 执行的代码
        
        Returns:
            列表 [(x1, y1, description1), (x2, y2, description2), ...]
        """
        clicks = []
        
        # 匹配 pyautogui.click(x, y) 格式
        pattern1 = r'pyautogui\.click\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)'
        matches1 = re.finditer(pattern1, code)
        for match in matches1:
            x, y = int(match.group(1)), int(match.group(2))
            line_start = code[:match.start()].rfind('\n')
            if line_start == -1:
                line_start = 0
            else:
                line_start += 1
            line_end = code.find('\n', match.start())
            if line_end == -1:
                line_end = len(code)
            line = code[line_start:line_end].strip()
            description = f"Click at ({x}, {y})"
            if '#' in line:
                comment = line.split('#', 1)[1].strip()
                description = f"{description} - {comment}"
            clicks.append((x, y, description))
        
        # 匹配 pyautogui.moveTo(x, y); pyautogui.click() 格式
        pattern2 = r'pyautogui\.moveTo\s*\(\s*(\d+)\s*,\s*(\d+)\s*\).*?pyautogui\.click\s*\('
        matches2 = re.finditer(pattern2, code, re.DOTALL)
        for match in matches2:
            x, y = int(match.group(1)), int(match.group(2))
            line_start = code[:match.start()].rfind('\n')
            if line_start == -1:
                line_start = 0
            else:
                line_start += 1
            line_end = code.find('\n', match.start())
            if line_end == -1:
                line_end = len(code)
            line = code[line_start:line_end].strip()
            description = f"MoveTo+Click at ({x}, {y})"
            if '#' in line:
                comment = line.split('#', 1)[1].strip()
                description = f"{description} - {comment}"
            clicks.append((x, y, description))
        
        return clicks
    
    def mark_screenshot_with_clicks(self, screenshot_path=None, action_code=None, step_id=None):
        """
        在截图上标记点击位置
        
        Args:
            screenshot_path: 截图路径 (如果为None则使用当前步骤的截图)
            action_code: 执行的代码 (如果为None则使用当前步骤的代码)
            step_id: 步骤ID (如果为None则使用当前步骤)
        
        Returns:
            标记后的截图路径
        """
        step_id = step_id or self.current_step
        
        # 查找步骤数据
        step_data = None
        for step in self.session_log["steps"]:
            if step["step_id"] == step_id:
                step_data = step
                break
        
        if not step_data:
            print(f"错误: 找不到步骤 {step_id} 的数据")
            return None
        
        # 如果未提供路径，使用步骤中记录的路径
        if not screenshot_path:
            screenshot_path = step_data.get("screenshot")
            if not screenshot_path:
                print(f"错误: 步骤 {step_id} 没有记录截图")
                return None
        
        # 如果未提供代码，使用步骤中记录的代码
        if not action_code:
            action_code_path = step_data.get("action_code")
            if not action_code_path:
                print(f"错误: 步骤 {step_id} 没有记录代码")
                return None
            with open(action_code_path, 'r', encoding='utf-8') as f:
                action_code = f.read()
        
        # 提取点击坐标
        clicks = self._extract_click_coordinates(action_code)
        if not clicks:
            print(f"信息: 步骤 {step_id} 的代码中没有检测到点击操作")
            return screenshot_path
        
        # 打开截图并标记
        try:
            img = Image.open(screenshot_path)
            draw = ImageDraw.Draw(img)
            
            for i, (x, y, description) in enumerate(clicks):
                # 画一个带标签的十字准线
                color = (255, 0, 0)  # 红色
                
                # 十字线
                draw.line((x-15, y, x+15, y), fill=color, width=2)
                draw.line((x, y-15, x, y+15), fill=color, width=2)
                
                # 圆圈
                draw.ellipse((x-20, y-20, x+20, y+20), outline=color, width=2)
                
                # 标签文本位置（避免超出图像边界）
                text_y = y + 25
                if text_y > img.height - 30:
                    text_y = y - 45
                
                # 标签背景和文本
                text = f"{i+1}: {description}"
                text_width, text_height = draw.textbbox((0, 0), text, font=self.font)[2:4]
                draw.rectangle((x-10, text_y, x+text_width, text_y+text_height), fill=(255, 255, 200))
                draw.text((x-5, text_y), text, font=self.font, fill=(0, 0, 0))
            
            # 保存标记后的图像
            marked_filename = f"step_{step_id}_marked_{int(time.time())}.png"
            marked_path = os.path.join(self.screenshots_dir, marked_filename)
            img.save(marked_path)
            
            # 更新步骤数据
            step_data["marked_screenshot"] = marked_path
            self._save_session_metadata()
            
            return marked_path
        
        except Exception as e:
            print(f"标记截图时出错: {e}")
            return screenshot_path
    
    def end_session(self, status="completed"):
        """
        结束会话记录
        
        Args:
            status: 会话状态 ('completed', 'failed' 或自定义状态)
        """
        self.session_log["end_time"] = time.time()
        self.session_log["status"] = status
        self.session_log["duration"] = self.session_log["end_time"] - self.session_log["start_time"]
        
        # 生成会话报告
        self._generate_session_report()
        
        # 保存最终会话数据
        self._save_session_metadata()
    
    def _generate_session_report(self):
        """生成会话报告"""
        report_path = os.path.join(self.session_dir, "session_report.md")
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(f"# Agent执行会话报告\n\n")
            f.write(f"**会话ID:** {self.session_id}\n\n")
            f.write(f"**开始时间:** {datetime.datetime.fromtimestamp(self.session_log['start_time']).strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**结束时间:** {datetime.datetime.fromtimestamp(self.session_log['end_time']).strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**持续时间:** {self.session_log['duration']:.2f} 秒\n\n")
            f.write(f"**状态:** {self.session_log['status']}\n\n")
            
            f.write(f"## 执行步骤记录\n\n")
            
            for step in self.session_log["steps"]:
                f.write(f"### 步骤 {step['step_id']}\n\n")
                
                f.write(f"**开始时间:** {datetime.datetime.fromtimestamp(step['start_time']).strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                if step.get("instruction"):
                    f.write(f"**指令:**\n```\n{step['instruction']}\n```\n\n")
                
                if step.get("thought"):
                    f.write(f"**思考过程:**\n```\n{step['thought'][:500]}{'...' if len(step['thought']) > 500 else ''}\n```\n\n")
                
                if step.get("action_code"):
                    rel_path = os.path.relpath(step["action_code"], self.session_dir)
                    f.write(f"**执行代码:** [查看完整代码]({rel_path})\n\n")
                
                if step.get("marked_screenshot"):
                    rel_path = os.path.relpath(step["marked_screenshot"], self.session_dir)
                    f.write(f"**标记截图:**\n\n![标记截图]({rel_path})\n\n")
                elif step.get("screenshot"):
                    rel_path = os.path.relpath(step["screenshot"], self.session_dir)
                    f.write(f"**截图:**\n\n![截图]({rel_path})\n\n")
                
                if step.get("execution_result"):
                    if isinstance(step["execution_result"], dict):
                        f.write(f"**执行结果:**\n```json\n{json.dumps(step['execution_result'], ensure_ascii=False, indent=2)}\n```\n\n")
                    else:
                        f.write(f"**执行结果:**\n```\n{step['execution_result']}\n```\n\n")
                
                f.write("\n---\n\n")
        
        return report_path
    
    def get_session_info(self):
        """
        获取会话信息
        
        Returns:
            会话信息字典
        """
        return {
            "session_id": self.session_id,
            "session_dir": self.session_dir,
            "steps_count": len(self.session_log["steps"]),
            "status": self.session_log["status"],
            "current_step": self.current_step
        }


# 示例使用
if __name__ == "__main__":
    # 创建日志记录器
    logger = AgentLogger(base_log_dir="logs")
    
    # 开始步骤
    logger.start_step("测试指令")
    
    # 记录截图
    test_img = Image.new('RGB', (800, 600), color='white')
    screenshot_path = logger.log_screenshot(test_img)
    
    # 记录动作
    test_code = """
    # 点击搜索框
    pyautogui.click(300, 210)  # 点击搜索框
    time.sleep(0.5)
    
    # 输入搜索内容
    pyautogui.write('news')
    time.sleep(0.5)
    
    # 点击搜索按钮
    pyautogui.moveTo(750, 210)
    pyautogui.click()  # 点击搜索按钮
    """
    logger.log_action(test_code, "我需要点击搜索框并输入内容")
    
    # 记录执行结果
    logger.log_execution_result({
        "status": True,
        "executed": True,
        "details": "代码成功执行"
    })
    
    # 标记截图
    logger.mark_screenshot_with_clicks()
    
    # 结束会话
    logger.end_session()
    
    print(f"日志已保存到: {logger.session_dir}") 