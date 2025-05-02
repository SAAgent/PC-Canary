from .prompt import SYS_PROMPT_SCREENSHOT_IN_CODE_OUT
import re
import base64
from PIL import Image
import io
import json
import platform
import subprocess
import pyautogui
import time
from typing import List, Dict, Any, Tuple, Optional, Union

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

from agent.models.base_model import BaseModel
from agent.models.openai_model import OpenAIModel # Import specific types for checking
from agent.models.claude_model import ClaudeModel
from agent.prompt import (
    SYS_PROMPT_SCREENSHOT_IN_CODE_OUT,
)  # Assuming this is used or similar

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

    def act(self, instruction: str, observation: Any, controller) -> Tuple[Optional[str], Optional[Dict], Optional[Dict]]:
        """
        根据指令和观察结果生成动作。

        Args:
            instruction: 任务指令。
            observation: 当前观察结果 (可以是 PIL Image, str, 或其他类型)。
            controller: 环境控制器。

        Returns:
            Tuple[Optional[str], Optional[Dict], Optional[Dict]]:
            - action (str | None): 如果是代码，则为代码字符串；如果是 'finish'，则为 "finish"；如果是其他特殊指令或错误，为 None 或指令名。
            - args (Dict | None): 如果 action 是 "finish"，则包含 'reasoning'；如果是代码，可能为 None；如果是其他指令，为 None。
            - usage_info (Dict | None): 包含 'prompt_tokens' 和 'completion_tokens' 的字典，如果可用。
        """
        # --- 1. 构建发送给 LLM 的 Messages 列表 --- #
        messages = []
        try:
            # --- 使用原始版本的逻辑构建 messages --- #
            screen_metadata = self._get_screen_metadata()
            system_content_text = (
                getattr(self, 'system_prompt', SYS_PROMPT_SCREENSHOT_IN_CODE_OUT) # Use loaded or default system prompt
                + "\nYou are asked to complete the following task: {}\n\n"
                + "Screen Context Metadata:\n{}"
            ).format(instruction, json.dumps(screen_metadata, indent=2))

            system_message = {"role": "system", "content": system_content_text}
            # Note: For multimodal models, system prompt might only support text.
            # If system prompt needs image, adjust accordingly.

            messages.append(system_message)

            # Add history (if applicable)
            # for entry in self.history: # Assuming self.history exists
            #    messages.append(entry)

            # Build user message based on observation type
            user_message_content = []
            user_prompt_text = getattr(self, 'user_message_text', "Analyze the observation and perform the next step.") # Get user text or default
            user_message_content.append({"type": "text", "text": user_prompt_text})

            if self.observation_type == 'screenshot':
                if observation is None:
                    raise ValueError("Screenshot observation is None")
                
                image_url = None
                if isinstance(observation, Image.Image):
                    buffered = io.BytesIO()
                    observation.save(buffered, format="PNG") # Use PNG for better quality usually
                    image_str = base64.b64encode(buffered.getvalue()).decode('utf-8')
                    image_url = f"data:image/png;base64,{image_str}"
                elif isinstance(observation, str) and observation.startswith("data:image"): # If already base64 string
                    image_url = observation
                elif isinstance(observation, str): # Treat as file path?
                     try:
                         with Image.open(observation) as img:
                              buffered = io.BytesIO()
                              img.save(buffered, format="PNG")
                              image_str = base64.b64encode(buffered.getvalue()).decode('utf-8')
                              image_url = f"data:image/png;base64,{image_str}"
                     except Exception as img_err:
                          print(f"无法将字符串观察作为图片路径加载: {img_err}")
                          # Optionally add text representation if image fails
                          user_message_content[0]["text"] += f"\n(无法加载图片观察: {observation})"
                else:
                     print(f"警告: 不支持的截图观察类型 {type(observation)}，将仅使用文本。")
                     user_message_content[0]["text"] += f"\n(观察类型不受支持)"
                
                if image_url:
                     user_message_content.append({
                         "type": "image_url",
                         "image_url": {"url": image_url, "detail": "high"}
                     })

            else: # Handle other observation types
                user_message_content[0]["text"] += f"\nObservation Data:\n{str(observation)}"
            
            messages.append({"role": "user", "content": user_message_content})
            # --- 原始 messages 构建逻辑结束 --- #
        except Exception as build_err:
             print(f"构建 Prompt Messages 时出错: {build_err}")
             return None, {"error": f"Prompt building error: {build_err}"}, None

        # --- 2. 调用 LLM (保留新版本的逻辑) --- #
        response = None
        llm_content_str = None
        usage_info = None
        try:
            response = self.model.generate_content(messages)
            # ... (保留根据模型类型提取 llm_content_str 和 usage_info 的代码) ...
            if isinstance(self.model, OpenAIModel) and response:
                llm_content_str = response.choices[0].message.content
                if response.usage:
                    usage_info = {
                        "prompt_tokens": response.usage.prompt_tokens,
                        "completion_tokens": response.usage.completion_tokens
                    }
            elif isinstance(self.model, ClaudeModel) and response:
                llm_content_str = self.model.get_content(response)
                raw_usage = self.model.get_usage(response)
                if raw_usage:
                     usage_info = { # 转换为统一的字段名
                         "prompt_tokens": raw_usage.get("prompt_tokens"),
                         "completion_tokens": raw_usage.get("completion_tokens")
                     }
            else:
                print(f"警告：无法识别的模型类型 {type(self.model)} 或响应为空。")
                llm_content_str = str(response)
        except Exception as e:
            print(f"调用 LLM 时发生错误: {e}")
            return None, {"error": f"LLM API Error: {e}"}, None

        if not llm_content_str:
             print("错误：LLM 返回了空内容。")
             return None, {"error": "LLM returned empty content"}, usage_info

        # --- 3. 解析 LLM 输出 (保留新版本的逻辑) --- #
        # 记录原始响应到 history (如果需要)
        # self.history.append({"role": "user", "content": user_message_content}) # Add user message to history?
        # self.history.append({"role": "assistant", "content": llm_content_str}) # Add assistant response

        # 解析 'DONE', 'WAIT', 'FAIL' 或代码
        action = None
        args = None
        thought = None # Parse thought if possible/needed from llm_content_str

        stripped_content = llm_content_str.strip().upper()
        if stripped_content == "DONE":
            action = "finish"
            args = {"reasoning": "Agent reported task DONE"}
            thought = llm_content_str[:llm_content_str.upper().find("DONE")] # Crude thought extraction
        elif stripped_content == "WAIT":
            action = "wait"
            thought = llm_content_str[:llm_content_str.upper().find("WAIT")]
        elif stripped_content == "FAIL":
            action = "fail"
            args = {"reasoning": "Agent reported task FAIL"}
            thought = llm_content_str[:llm_content_str.upper().find("FAIL")]
        else:
            # 尝试提取代码
            code = self._extract_python_code(llm_content_str)
            if code:
                action = code
                # Extract thought if prompt asks for it before code block
                match = re.search(r"```python\n", llm_content_str, re.IGNORECASE)
                if match:
                     thought = llm_content_str[:match.start()].strip()
                else: # Fallback if only ``` found
                     match = re.search(r"```\n", llm_content_str, re.IGNORECASE)
                     if match:
                         thought = llm_content_str[:match.start()].strip()
            else:
                # Assume the whole thing is thought or error
                print("警告：未能从 LLM 输出中提取到代码或已知指令。")
                args = {"error": "Could not parse code or known instruction", "raw_output": llm_content_str}
                thought = llm_content_str # Treat whole output as thought/error message
        
        # --- 4. 记录历史 (如果需要) --- #
        # self.observations.append(user_message) # If tracking history like original
        # self.responses.append({"role": "assistant", "content": llm_content_str})

        # --- 5. 返回结果 --- #
        # 打印思考 (如果提取了)
        if thought:
             print(f"\nAgent思考:")
             print("-" * 50)
             print(thought[:500] + ("..." if len(thought) > 500 else ""))
             print("-" * 50)

        return action, args, usage_info

    def _build_prompt_messages(self, instruction, observation, history) -> List[Dict[str, Any]]:
        # This function is now integrated into act() above. Can be removed or kept for modularity.
        # If kept, needs signature change to match how act() calls it.
        # For now, removing the separate definition as logic is in act()
        pass

    def _extract_python_code(self, text: str) -> Optional[str]:
        """ 从文本中提取被 ```python ... ``` 包裹的代码块。"""
        match = re.search(r"```python\n(.*?)\n```", text, re.DOTALL)
        if match:
            return match.group(1).strip()
        # 如果没有找到 ```python ... ```，也尝试查找普通的 ``` ... ```
        match = re.search(r"```\n(.*?)\n```", text, re.DOTALL)
        if match:
             print("警告: 找到了普通的 ``` 代码块，将尝试作为 Python 代码使用。")
             return match.group(1).strip()
        return None

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
