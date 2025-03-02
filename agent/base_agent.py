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

        self.thoughts = []
        self.observations = []
        self.actions = []

        # TODO  根据不同的输入输出写不同的 prompt，最好比他们的版本好，这里应该实现最简单的版本
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
            "active_window": {},
            "operating_system": {},
            "scale_factor": {}
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
                        
                        # 计算缩放因子 (近似值)
                        # 标准 DPI 是 96，所以缩放因子可以通过实际 DPI / 96 计算
                        if primary_monitor.width_mm and primary_monitor.height_mm:
                            dpi_x = primary_monitor.width / (primary_monitor.width_mm / 25.4)
                            dpi_y = primary_monitor.height / (primary_monitor.height_mm / 25.4)
                            avg_dpi = (dpi_x + dpi_y) / 2
                            scale_factor = avg_dpi / 96.0
                            metadata["scale_factor"] = {
                                "value": round(scale_factor, 2),
                                "dpi": round(avg_dpi)
                            }
                except Exception as e:
                    metadata["screen_resolution"]["error"] = str(e)
            
            except Exception as e:
                metadata["screen_resolution"]["error"] = str(e)
        
        # 获取活动窗口信息（如果可用）
        if GW_AVAILABLE:
            try:
                active_window = gw.getActiveWindow()
                if active_window:
                    metadata["active_window"] = {
                        "title": active_window.title,
                        "left": active_window.left,
                        "top": active_window.top,
                        "width": active_window.width,
                        "height": active_window.height
                    }
            except Exception as e:
                metadata["active_window"] = {"error": str(e)}
        else:
            # 在不支持pygetwindow的平台上尝试替代方法
            if platform.system() == "Linux":
                try:
                    # 尝试使用xprop获取活动窗口信息（如果安装了xprop）
                    try:
                        window_id = subprocess.check_output("xprop -root _NET_ACTIVE_WINDOW", shell=True).decode().strip().split()[-1]
                        if window_id != "0x0":
                            window_info = subprocess.check_output(f"xwininfo -id {window_id}", shell=True).decode().strip()
                            
                            # 解析窗口标题
                            title_match = re.search(r'\"(.+?)\"', window_info)
                            title = title_match.group(1) if title_match else "Unknown"
                            
                            # 解析窗口位置和大小
                            x_match = re.search(r'Absolute upper-left X:\s+(\d+)', window_info)
                            y_match = re.search(r'Absolute upper-left Y:\s+(\d+)', window_info)
                            width_match = re.search(r'Width:\s+(\d+)', window_info)
                            height_match = re.search(r'Height:\s+(\d+)', window_info)
                            
                            if x_match and y_match and width_match and height_match:
                                metadata["active_window"] = {
                                    "title": title,
                                    "left": int(x_match.group(1)),
                                    "top": int(y_match.group(1)),
                                    "width": int(width_match.group(1)),
                                    "height": int(height_match.group(1))
                                }
                    except Exception as e:
                        metadata["active_window"] = {"error": f"Failed to get window info: {str(e)}"}
                except Exception as e:
                    metadata["active_window"] = {"error": f"Linux window detection failed: {str(e)}"}
            else:
                metadata["active_window"] = {"error": "Window information not available on this platform"}
        
        # 如果无法获取缩放因子，尝试使用系统特定的方法
        if "value" not in metadata.get("scale_factor", {}):
            try:
                if platform.system() == "Windows":
                    # Windows 系统使用 PowerShell 获取缩放因子
                    cmd = "powershell \"Get-CimInstance -Namespace root\\cimv2\\terminal-services -ClassName Win32_TerminalServiceSetting | Select-Object ScreenScaleFactor\""
                    result = subprocess.check_output(cmd, shell=True).decode().strip()
                    scale_line = [line for line in result.split('\n') if line.strip().isdigit()]
                    if scale_line:
                        scale_factor = int(scale_line[0].strip()) / 100
                        metadata["scale_factor"] = {"value": scale_factor}
                elif platform.system() == "Darwin":  # macOS
                    cmd = "osascript -e 'tell application \"Finder\" to get bounds of window of desktop'"
                    result = subprocess.check_output(cmd, shell=True).decode().strip()
                    # 解析结果并与实际屏幕分辨率比较来估算缩放因子
                    if result:
                        bounds = [int(x) for x in result.replace("{", "").replace("}", "").split(", ")]
                        if len(bounds) == 4:
                            logical_width = bounds[2] - bounds[0]
                            logical_height = bounds[3] - bounds[1]
                            scale_x = screen_width / logical_width
                            scale_y = screen_height / logical_height
                            scale_factor = (scale_x + scale_y) / 2
                            metadata["scale_factor"] = {"value": round(scale_factor, 2)}
                elif platform.system() == "Linux":
                    # 在Linux上尝试使用xrdb或X资源数据库获取DPI信息
                    try:
                        # 尝试从xrandr获取DPI信息
                        cmd = "xrandr | grep -o 'connected.*\\b[0-9]\\+mm x [0-9]\\+mm\\b' | head -1"
                        result = subprocess.check_output(cmd, shell=True).decode().strip()
                        
                        # 尝试解析物理尺寸
                        mm_match = re.search(r'(\d+)mm x (\d+)mm', result)
                        if mm_match:
                            width_mm = int(mm_match.group(1))
                            height_mm = int(mm_match.group(2))
                            
                            if width_mm > 0 and height_mm > 0:
                                dpi_x = screen_width / (width_mm / 25.4) 
                                dpi_y = screen_height / (height_mm / 25.4)
                                avg_dpi = (dpi_x + dpi_y) / 2
                                scale_factor = avg_dpi / 96.0
                                metadata["scale_factor"] = {
                                    "value": round(scale_factor, 2),
                                    "dpi": round(avg_dpi),
                                    "calculation_method": "xrandr"
                                }
                    except Exception:
                        # 后备方法：尝试从xdpyinfo获取
                        try:
                            cmd = "xdpyinfo | grep -B 2 resolution"
                            result = subprocess.check_output(cmd, shell=True).decode().strip()
                            dpi_match = re.search(r'(\d+)x(\d+) dots per inch', result)
                            if dpi_match:
                                dpi = int(dpi_match.group(1))
                                scale_factor = dpi / 96.0
                                metadata["scale_factor"] = {
                                    "value": round(scale_factor, 2),
                                    "dpi": dpi,
                                    "calculation_method": "xdpyinfo"
                                }
                            else:
                                # 如果都失败，默认为1.0
                                metadata["scale_factor"] = {"value": 1.0, "note": "Default value for Linux"}
                        except:
                            metadata["scale_factor"] = {"value": 1.0, "note": "Default value for Linux"}
            except Exception as e:
                # 如果所有方法都失败，使用默认值
                metadata["scale_factor"] = {"value": 1.0, "error": str(e)}
        
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
                    "text": self.system_message_text
                    + "\nYou are asked to complete the following task: {}\n\n"
                    + "Screen Context Metadata:\n{}"
                    .format(
                        instruction,
                        json.dumps(screen_metadata, indent=2)
                    ),
                },
            ],
        }

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

        # 添加历史对话
        assert len(self.observations) == len(self.actions) and len(self.actions) == len(
            self.thoughts
        ), "The number of observations and actions should be the same."

        # 构建完整消息历史
        messages.append(system_message)

        # 添加历史交互
        for i in range(len(self.thoughts)):
            messages.append(self.observations[i])
            messages.append(self.thoughts[i])
            messages.append(self.actions[i])

        # 添加当前的观察
        messages.append(user_message)

        # 调用模型获取响应
        response = self.model.generate_content(messages)

        # 提取思考和代码
        thought, action_code = self._parse_response(response.text)

        # 记录交互历史
        self.thoughts.append(thought)
        self.observations.append(user_message)
        self.actions.append(action_code)

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

        # 这里需要安全地执行代码，实际实现中应该有更多的安全检查
        try:
            # 创建一个局部环境，包含控制器
            local_env = {
                'pyautogui': controller,
                'time': __import__('time'),
            }

            # 执行代码
            exec(action_code, {}, local_env)
            return True
        except Exception as e:
            print(f"执行代码时出错: {e}")
            return False
