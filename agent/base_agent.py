from .prompt import SYS_PROMPT_SCREENSHOT_IN_CODE_OUT
import re
import base64
from PIL import Image
import io
import json
import platform
import subprocess
import pyautogui

# 导入获取屏幕和窗口信息的库
# 为不同平台选择合适的窗口管理库
SCREEN_INFO_AVAILABLE = False
GW_AVAILABLE = False
try:
    # 尝试导入screeninfo库用于获取显示器信息
    from screeninfo import get_monitors
    SCREEN_INFO_AVAILABLE = True
except ImportError:
    pass

try:
    # 根据操作系统选择合适的窗口管理库
    if platform.system() == "Windows":
        import pygetwindow as gw
        GW_AVAILABLE = True
    elif platform.system() == "Darwin":  # macOS
        import pygetwindow as gw
        GW_AVAILABLE = True
    elif platform.system() == "Linux":
        # Linux下pygetwindow不可用，可选择性地尝试其他方法
        # 例如可以尝试使用xlib或其他Linux特定的方法
        GW_AVAILABLE = False
        # 可以在这里添加Linux特定的窗口信息获取方法
except ImportError:
    GW_AVAILABLE = False


class BaseAgent:
    def __init__(self, model, observation_type, action_space) -> None:
        self.model = model
        self.action_space = action_space
        self.observation_type = observation_type

        self.observations = []
        self.responses = []

        # TODO  支持更多样的版本
        if observation_type == "screenshot" and action_space == "pyautogui-muti-action":
            self.system_message_text = SYS_PROMPT_SCREENSHOT_IN_CODE_OUT
            self.user_message_text = "Given the screenshot as below. What's the next step that you will do to help with the task?"

    def _get_screen_metadata(self):
        """
        收集屏幕元数据，包括分辨率、鼠标位置、活动窗口信息等
        针对各种平台进行了优化处理
        
        Returns:
            dict: 包含屏幕元数据的字典
        """
        metadata = {
            "screen_resolution": {},
            "mouse_position": {},
            "windows": [],
            "operating_system": {},
        }
        
        # 获取操作系统信息
        metadata["operating_system"] = {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version()
        }
        
        # 获取鼠标位置
        mouse_x, mouse_y = pyautogui.position()
        metadata["mouse_position"] = {
            "x": mouse_x,
            "y": mouse_y
        }
        
        # 获取屏幕分辨率
        screen_width, screen_height = pyautogui.size()
        metadata["screen_resolution"] = {
            "width": screen_width,
            "height": screen_height
        }
        
        # 尝试获取更详细的屏幕信息
        if SCREEN_INFO_AVAILABLE:
            try:
                # 获取显示器信息和缩放因子
                try:
                    monitors = get_monitors()
                    if monitors:
                        primary_monitor = next((m for m in monitors if m.is_primary), monitors[0])
                        metadata["screen_resolution"]["width_mm"] = primary_monitor.width_mm
                        metadata["screen_resolution"]["height_mm"] = primary_monitor.height_mm
                except Exception as e:
                    metadata["screen_resolution"]["error"] = str(e)
            
            except Exception as e:
                metadata["screen_resolution"]["error"] = str(e)
        
        # 获取所有窗口信息
        window_list = []
        try:
            # 获取窗口列表 (通过wmctrl)
            wmctrl_output = subprocess.check_output("wmctrl -l -G", shell=True).decode().strip()
            for line in wmctrl_output.split('\n'):
                if line.strip():
                    parts = line.split(None, 7)
                    if len(parts) >= 8:
                        win_id, desktop, x, y, width, height, host, title = parts
                        window_list.append({
                            "id": win_id,
                            "desktop": desktop,
                            "x": int(x),
                            "y": int(y),
                            "width": int(width),
                            "height": int(height),
                            "title": title,
                            "host": host,
                            "source": "wmctrl"
                        })
        except Exception as e:
            return [{
                "error": f"wmctrl执行失败: {str(e)}",
                "source": "wmctrl_error"
            }]
        metadata["windows"] = window_list
        return metadata

    def act(self, instruction:str, observation=None, controller=None):
        """
        根据指令和观察，执行一次决策-行动循环
        
        Args:
            instruction: 用户指令
            observation: 环境观察（如截图）
            controller: GUI控制器实例
            
        Returns:
            action: 执行的动作
            thought: 决策思考过程
        """
        messages = []
        
        # 获取屏幕元数据
        screen_metadata = self._get_screen_metadata()
        
        # 将元数据添加到系统消息中
        system_message = {
            "role": "system",
            "content": [
                {
                    "type": "text",
                    "text": (self.system_message_text
                    + "\nYou are asked to complete the following task: {}\n\n"
                    + "Screen Context Metadata:\n{}")
                    .format(
                        instruction,
                        json.dumps(screen_metadata, indent=2)
                    ),
                },
            ],
        }
        if len(messages) == 0:
            messages.append(system_message)
        else:
            messages[0] = system_message
        # 构建用户消息（包含观察信息）
        if self.observation_type == 'screenshot':
            # 确保有观察数据
            if observation is None:
                raise ValueError("观察数据不能为空")

            # 如果是PIL图像格式，转换为base64字符串
            if isinstance(observation, Image.Image):
                buffered = io.BytesIO()
                observation.save(buffered, format="PNG")
                image_str = base64.b64encode(buffered.getvalue()).decode('utf-8')
                image_url = f"data:image/png;base64,{image_str}"
            # 如果已经是base64字符串或URL
            elif isinstance(observation, str):
                image_url = observation
            else:
                raise ValueError("不支持的数据类型")

            user_message = {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": self.user_message_text,
                    },
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": image_url,
                            "detail": "high",
                        },
                    },
                ],
            }
        else:
            # 处理其他类型的观察
            user_message = {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": self.user_message_text + "\n" + str(observation),
                    },
                ],
            }
        # print(system_message["content"][0]["text"])
        # print(user_message["content"][0]["text"])
        # 添加历史对话
        assert len(self.observations) == len(self.responses), "The number of observations and actions should be the same."

        # 构建完整消息历史
        messages.append(system_message)

        # 添加历史交互
        for i in range(len(self.observations)):
            messages.append(self.observations[i])
            messages.append(self.responses[i])

        # 添加当前的观察
        messages.append(user_message)
        # 调用模型获取响应
        response = self.model.generate_content(messages)

        # 提取思考和代码
        thought, action_code = self._parse_response(response.choices[0].message.content)

        # 记录交互历史
        self.observations.append(user_message)
        self.responses.append({
            "role": "assistant",
            "content": response.choices[0].message.content
        })

        # 如果提供了控制器，则执行动作
        if controller is not None and action_code not in ["WAIT", "FAIL", "DONE"]:
            self._execute_action(action_code, controller)

        return action_code, thought

    def _parse_response(self, response_text):
        # TODO 测试该函数
        """解析模型响应，提取思考过程和代码"""
        # 分离思考和代码部分
        code_match = re.search(r'```python\s*(.*?)\s*```', response_text, re.DOTALL)

        # 特殊代码检查 (WAIT, FAIL, DONE)
        special_code_match = re.search(r'```\s*(WAIT|FAIL|DONE)\s*```', response_text)

        if special_code_match:
            code = special_code_match.group(1)
            # 思考是代码之前的所有内容
            thought = response_text[:special_code_match.start()].strip()
        elif code_match:
            code = code_match.group(1).strip()
            # 思考是代码之前的所有内容
            thought = response_text[:code_match.start()].strip()
        else:
            # 没有找到代码块，将整个响应作为思考
            thought = response_text.strip()
            code = ""

        return thought, code

    def _execute_action(self, action_code, controller):
        # 将代码执行逻辑委托给controller处理
        try:
            # 检查controller是否存在执行代码的方法
            if hasattr(controller, 'execute') and callable(controller.execute):
                # 兼容可能使用execute方法的controller
                return controller.execute(action_code)
        except Exception as e:
            print(f"执行代码时出错: {e}")
            return False
