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
from typing import List, Dict, Any, Tuple, Optional

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
from agent.prompt import PYAUTOGUI_PROMPT_TEMPLATE # Assuming this is used or similar

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

    def act(self, instruction: str, observation: Dict[str, Any], controller) -> Tuple[Optional[str], Optional[Dict], Optional[Dict]]:
        """
        根据指令和观察结果生成动作。

        Args:
            instruction: 任务指令。
            observation: 当前观察结果 (包含截图、元数据等)。
            controller: 环境控制器 (用于潜在的交互或状态获取)。

        Returns:
            Tuple[Optional[str], Optional[Dict], Optional[Dict]]:
            - action (str | None): 如果是代码，则为代码字符串；如果是 'finish'，则为 "finish"；如果是其他特殊指令或错误，为 None 或指令名。
            - args (Dict | None): 如果 action 是 "finish"，则包含 'reasoning'；如果是代码，可能为 None；如果是其他指令，为 None。
            - usage_info (Dict | None): 包含 'prompt_tokens' 和 'completion_tokens' 的字典，如果可用。
        """
        screenshot = observation.get('screenshot')
        if not screenshot:
            print("错误：观察结果中缺少屏幕截图。")
            return None, {"error": "Missing screenshot"}, None # Return error indication

        # --- 构建 Prompt ---
        # (假设你在这里构建 messages 列表，包括系统提示、历史、当前观察等)
        # 例如:
        messages = self._build_prompt_messages(instruction, observation, self.history)

        # --- 调用 LLM ---
        response = None
        llm_content_str = None
        usage_info = None
        try:
            response = self.model.generate_content(messages)

            # --- 根据模型类型提取内容和 Usage ---
            if isinstance(self.model, OpenAIModel) and response:
                llm_content_str = response.choices[0].message.content
                if response.usage:
                    usage_info = {
                        "prompt_tokens": response.usage.prompt_tokens,
                        "completion_tokens": response.usage.completion_tokens
                    }
            elif isinstance(self.model, ClaudeModel) and response:
                # 使用辅助方法获取内容
                llm_content_str = self.model.get_content(response)
                # 使用辅助方法获取 usage
                raw_usage = self.model.get_usage(response)
                if raw_usage:
                     usage_info = { # 转换为统一的字段名
                         "prompt_tokens": raw_usage.get("prompt_tokens"),
                         "completion_tokens": raw_usage.get("completion_tokens")
                     }
            else:
                print(f"警告：无法识别的模型类型 {type(self.model)} 或响应为空，无法提取内容/usage。")
                llm_content_str = str(response) # 尝试转为字符串

        except Exception as e:
            print(f"调用 LLM 时发生错误: {e}")
            # 在 run_agent_with_eval 中记录 LLM_QUERY_END(error)
            return None, {"error": f"LLM API Error: {e}"}, None # Return error indication

        if not llm_content_str:
             print("错误：LLM 返回了空内容。")
             return None, {"error": "LLM returned empty content"}, usage_info # Return error, but include usage if available

        # --- 解析 LLM 输出 ---
        # 1. 检查是否是特殊指令 DONE
        if llm_content_str.strip().upper() == "DONE":
            print("Agent 报告任务完成 (DONE)。")
            # 返回特殊标记，让调用者知道
            action = "finish"
            args = {"reasoning": "Agent reported task DONE"}
            self.history.append({"role": "assistant", "content": llm_content_str}) # 记录原始输出
            return action, args, usage_info

        # 2. 检查其他特殊指令 (WAIT, FAIL) - 可选，取决于你的 prompt
        elif llm_content_str.strip().upper() == "WAIT":
             print("Agent 请求等待。")
             action = "wait"
             args = None
             self.history.append({"role": "assistant", "content": llm_content_str})
             return action, args, usage_info
        elif llm_content_str.strip().upper() == "FAIL":
             print("Agent 报告任务失败 (FAIL)。")
             action = "fail"
             args = {"reasoning": "Agent reported task FAIL"}
             self.history.append({"role": "assistant", "content": llm_content_str})
             return action, args, usage_info

        # 3. 尝试提取 Python 代码块
        code = self._extract_python_code(llm_content_str)
        if code:
            print("提取到 Python 代码块。")
            action = code # 直接返回代码字符串作为 action
            args = None # 代码没有额外参数
            # 记录包含代码的原始输出或仅记录代码？取决于历史记录的需求
            self.history.append({"role": "assistant", "content": llm_content_str}) # 记录完整原始输出
            # self.history.append({"role": "assistant", "content": f"```python\\n{code}\\n```"}) # 或只记录代码
            return action, args, usage_info
        else:
            print("警告：未能从 LLM 输出中提取到有效的 Python 代码块或 DONE/WAIT/FAIL 指令。")
            print(f"原始输出: {llm_content_str}")
            # 返回原始文本，让调用者决定如何处理？或者视为错误？
            action = None
            args = {"error": "Could not parse code or known instruction", "raw_output": llm_content_str}
            self.history.append({"role": "assistant", "content": llm_content_str}) # 记录原始输出
            return action, args, usage_info

    def _build_prompt_messages(self, instruction, observation, history) -> List[Dict[str, Any]]:
        """ Helper function to build the messages list for the LLM. """
        # --- 这里实现你构建 messages 列表的逻辑 ---
        # 例如:
        messages = []
        # 1. 添加系统 Prompt (假设你的 prompt 文件加载到了 self.system_prompt)
        # 你可能需要从 self.system_prompt (或类似变量) 获取基础系统提示
        # SYS_PROMPT_SCREENSHOT_IN_CODE_OUT 应该在这里被使用
        system_prompt = getattr(self, 'system_prompt', SYS_PROMPT_SCREENSHOT_IN_CODE_OUT) # 获取或使用默认
        messages.append({"role": "system", "content": system_prompt})

        # 2. 添加历史记录 (如果需要)
        # for entry in history:
        #    messages.append(entry)

        # 3. 添加当前指令和观察
        # 需要将截图和元数据格式化为模型可接受的格式
        # 对于多模态模型，截图通常作为 content 列表的一部分
        prompt_text = f"用户指令: {instruction}\\n\\n当前屏幕元数据: {json.dumps(observation.get('metadata', {}))}\\n\\n请分析截图并生成下一步操作。"
        content = [{"type": "text", "text": prompt_text}]
        screenshot_base64 = observation.get('screenshot_base64') # 假设观察结果中有 base64 截图

        if screenshot_base64:
            # (这里的 base64 处理逻辑应该与 ClaudeModel 中的类似，或统一处理)
            media_type = "image/png" # 假设
            if screenshot_base64.startswith("data:image/jpeg;base64,"):
                media_type = "image/jpeg"
                screenshot_base64 = screenshot_base64.split(",")[1]
            elif screenshot_base64.startswith("data:image/png;base64,"):
                media_type = "image/png"
                screenshot_base64 = screenshot_base64.split(",")[1]

            content.append({
                "type": "image_url", # OpenAI 格式
                "image_url": {
                     # Claude 模型处理时会转换这个
                    "url": f"data:{media_type};base64,{screenshot_base64}"
                 }
            })
        else:
             print("警告: 观察结果中缺少 base64 截图，模型将仅基于文本分析。")


        messages.append({"role": "user", "content": content})

        return messages

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
