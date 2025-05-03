# agent/models/claude_model.py
import os
import time # For retry delay
import anthropic
import httpx
from typing import List, Dict, Any, Optional
from agent.models.base_model import BaseModel # 假设有一个基类，或直接实现所需方法
from anthropic.types import Message # Import the response type

class ClaudeModel(BaseModel):
    """
    Anthropic Claude 模型封装。
    接口与 OpenAIModel 对齐。
    """
    def __init__(
        self,
        api_key: str = None,
        model_name: str = "claude-3-7-sonnet-latest",
        temperature: float = 0.2,
        max_tokens: int = 2048,
        max_retries: int = 3,  # Added
        retry_delay: float = 1.0,  # Added
    ):
        super().__init__()
        self.model_name = model_name
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        # 优先使用传入的 API Key，否则从环境变量 ANTHROPIC_API_KEY 读取
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("Anthropic API Key 未提供，请通过参数或环境变量 ANTHROPIC_API_KEY 设置。")

        self.client = anthropic.Anthropic(api_key=self.api_key, max_retries=0) # Set client retries to 0, handle manually
        print(f"Claude 模型已初始化: {self.model_name}")

    # Renamed from generate to generate_content
    def generate_content(self, messages: List[Dict[str, Any]]) -> Message:
        """
        使用 Claude 模型生成内容，输入输出接口与 OpenAIModel 类似。

        Args:
            messages: OpenAI 格式的消息列表。
                      其中 role='system' 的消息会被提取为 system prompt。
                      role='user' 的消息 content 可以是字符串或包含 text/image 的列表。

        Returns:
            anthropic.types.Message: Claude API 的原始响应对象。
                                     调用者需要从中提取内容 (e.g., response.content[0].text)
                                     和使用情况 (e.g., response.usage.input_tokens)。
        """
        system_prompt = "You are a helpful assistant." # Default system prompt
        processed_messages = []

        # 1. Extract system prompt and process messages
        temp_messages = []
        for msg in messages:
            role = msg.get("role")
            content = msg.get("content")

            if role == "system":
                # Assume system prompt is simple text for Claude
                if isinstance(content, str):
                    system_prompt = content
                elif isinstance(content, list) and len(content) > 0 and content[0].get("type") == "text":
                    system_prompt = content[0].get("text", system_prompt)
                continue # Don't add system message to the main list for Claude

            if role in ["user", "assistant"]:
                # Handle potentially complex content (text + images for user role)
                if role == "user" and isinstance(content, list):
                    claude_content = []
                    for item in content:
                        item_type = item.get("type")
                        if item_type == "text":
                            claude_content.append({"type": "text", "text": item.get("text", "")})
                        elif item_type == "image_url": # Adapt from OpenAI format
                            image_url = item.get("image_url", {}).get("url", "")
                            if image_url.startswith("data:image/"):
                                # Extract base64 data and media type
                                try:
                                    header, encoded = image_url.split(",", 1)
                                    media_type = header.split(";")[0].split(":")[1]
                                    claude_content.append({
                                         "type": "image",
                                         "source": {
                                             "type": "base64",
                                             "media_type": media_type,
                                             "data": encoded,
                                         },
                                     })
                                except Exception as e:
                                    print(f"无法解析 base64 图片 URL: {e}")
                            else:
                                print(f"不支持的图片 URL 格式: {image_url}") # Claude might not support direct URLs
                elif isinstance(content, str):
                    # Simple text content for user or assistant
                    claude_content = content
                else:
                    print(f"警告: 忽略了不支持的消息内容格式 for role {role}: {content}")
                    continue # Skip unsupported format

                temp_messages.append({"role": role, "content": claude_content})

        # Filter out consecutive messages from the same role if needed (Claude might require alternation)
        if not temp_messages:
            raise ValueError("消息列表处理后为空，无法调用 Claude API。")

        processed_messages.append(temp_messages[0])
        for i in range(1, len(temp_messages)):
            if temp_messages[i]["role"] != temp_messages[i-1]["role"]:
                processed_messages.append(temp_messages[i])
            else:
                # Handle consecutive messages e.g. merge user messages? For now just log.
                print(f"警告: 连续消息来自同一角色 ({temp_messages[i]['role']}), Claude 可能不支持。将尝试发送。")
                processed_messages.append(temp_messages[i])

        # 2. Call Claude API with retry logic
        for attempt in range(self.max_retries):
            try:
                print(f"向 Claude ({self.model_name}) 发送请求 (Attempt {attempt + 1}/{self.max_retries})...")
                response = self.client.messages.create(
                    model=self.model_name,
                    max_tokens=self.max_tokens,
                    temperature=self.temperature,
                    system=system_prompt,
                    messages=processed_messages
                )
                # print(f"收到 Claude 响应: {response.content[0].text[:100]}...")
                # Return the full response object
                return response

            except anthropic.APIConnectionError as e:
                print(f"Claude API 连接错误: {e}")
                if attempt < self.max_retries - 1:
                    wait_time = self.retry_delay * (2 ** attempt)
                    print(f"等待 {wait_time:.2f} 秒后重试...")
                    time.sleep(wait_time)
                else:
                    raise ConnectionError(f"Claude API 连接错误达到最大重试次数: {e}") from e
            except anthropic.RateLimitError as e:
                print(f"Claude API 速率限制错误: {e}")
                if attempt < self.max_retries - 1:
                    wait_time = self.retry_delay * (2 ** attempt)
                    print(f"等待 {wait_time:.2f} 秒后重试...")
                    time.sleep(wait_time)
                else:
                    raise Exception(f"Claude API 速率限制错误达到最大重试次数: {e}") from e
            except anthropic.APIStatusError as e:
                print(f"Claude API 状态错误 (非 2xx): status_code={e.status_code}, response={e.response}")
                # Don't retry on non-transient errors like 4xx
                if e.status_code >= 400 and e.status_code < 500:
                    raise Exception(f"Claude API 客户端错误: {e}") from e
                # Retry on 5xx potentially
                if attempt < self.max_retries - 1:
                    wait_time = self.retry_delay * (2 ** attempt)
                    print(f"等待 {wait_time:.2f} 秒后重试...")
                    time.sleep(wait_time)
                else:
                    raise Exception(f"Claude API 服务端错误达到最大重试次数: {e}") from e
            except Exception as e:
                print(f"调用 Claude API 时发生未知错误: {e}")
                # Depending on the error, might want to retry or raise immediately
                # For now, raise after max retries
                if attempt == self.max_retries - 1:
                    raise Exception(f"调用 Claude API 时发生未知错误达到最大重试次数: {e}") from e
                else:
                    wait_time = self.retry_delay * (2 ** attempt)
                    print(f"等待 {wait_time:.2f} 秒后重试...")
                    time.sleep(wait_time)

        # Should not be reached if max_retries > 0, but satisfy linters
        raise Exception("Claude API 调用在所有重试后失败。")

    # --- Helper/Compatibility methods (Optional but good for consistency) ---

    # Example: Method to get text content easily, mimicking openai response access
    def get_content(self, response: Message) -> Optional[str]:
        if response and response.content and isinstance(response.content, list) and len(response.content) > 0:
            # Assuming the main text content is in the first block
            if hasattr(response.content[0], 'text'):
                return response.content[0].text
        return None

    # Example: Method to get usage, mimicking openai response access
    def get_usage(self, response: Message) -> Optional[Dict[str, int]]:
        if response and response.usage:
            return {
                 "prompt_tokens": response.usage.input_tokens,
                 "completion_tokens": response.usage.output_tokens,
                 "total_tokens": response.usage.input_tokens + response.usage.output_tokens
             }
        return None

    def _validate_api_key(self): # Ensure compatibility if BaseAgent calls this
        if not self.api_key:
            raise ValueError("Anthropic API Key 未设置。")

    # 可能需要实现其他 BaseLLM 中的方法
