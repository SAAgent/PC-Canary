"""
OpenAI 模型接口

提供与 OpenAI API 交互的统一接口
"""

import json
import requests
from typing import List, Dict, Any, Optional, Union
import time

from .base_model import BaseModel


class OpenAIModelResponse:
    """
    OpenAI 模型响应封装
    """
    
    def __init__(self, response_data: Dict[str, Any]):
        """
        初始化响应对象
        
        Args:
            response_data: API 响应数据
        """
        self.response_data = response_data
        self._extract_content()
    
    def _extract_content(self):
        """从响应中提取文本内容"""
        try:
            self.text = self.response_data.get("choices", [{}])[0].get("message", {}).get("content", "")
        except (IndexError, KeyError):
            self.text = ""
    
    def __str__(self):
        return self.text


class OpenAIModel(BaseModel):
    """
    OpenAI 模型接口
    
    提供与 OpenAI API 交互的方法
    """
    
    def __init__(self, 
                 api_key: str, 
                 model_name: str = "gpt-4o", 
                 api_base: str = "https://api.openai.com/v1", 
                 max_retries: int = 3,
                 retry_delay: float = 1.0,
                 temperature: float = 0.7,
                 top_p: float = 1.0,
                 max_tokens: Optional[int] = None,
                 **kwargs):
        """
        初始化 OpenAI 模型
        
        Args:
            api_key: OpenAI API 密钥
            model_name: 模型名称，默认为 "gpt-4o"
            api_base: API 基础 URL
            max_retries: 最大重试次数
            retry_delay: 重试间隔（秒）
            temperature: 温度参数，控制随机性
            top_p: 控制生成多样性
            max_tokens: 最大生成令牌数
            **kwargs: 其他参数
        """
        super().__init__(api_key=api_key, model_name=model_name, **kwargs)
        self.api_base = api_base
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.temperature = temperature
        self.top_p = top_p
        self.max_tokens = max_tokens
    
    def generate_content(self, messages: List[Dict[str, Any]]) -> OpenAIModelResponse:
        """
        生成内容
        
        Args:
            messages: 消息列表，包含对话历史
            
        Returns:
            OpenAIModelResponse 对象
        
        Raises:
            ValueError: API 密钥无效或其他参数错误
            ConnectionError: 网络连接错误
            TimeoutError: 请求超时
            Exception: 其他错误
        """
        self._validate_api_key()
        formatted_messages = self._format_messages(messages)
        
        # 构建请求参数
        payload = {
            "model": self.model_name,
            "messages": formatted_messages,
            "temperature": self.temperature,
            "top_p": self.top_p,
        }
        
        if self.max_tokens:
            payload["max_tokens"] = self.max_tokens
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        
        # 发送请求，带重试机制
        for attempt in range(self.max_retries):
            try:
                response = requests.post(
                    f"{self.api_base}/chat/completions",
                    headers=headers,
                    data=json.dumps(payload),
                    timeout=60
                )
                
                # 检查响应状态
                if response.status_code == 200:
                    return OpenAIModelResponse(response.json())
                elif response.status_code == 429:
                    # 速率限制，等待后重试
                    retry_after = int(response.headers.get("Retry-After", self.retry_delay))
                    print(f"触发速率限制，等待 {retry_after} 秒后重试...")
                    time.sleep(retry_after)
                    continue
                else:
                    # 其他错误
                    error_msg = f"API 请求失败: HTTP {response.status_code}"
                    try:
                        error_data = response.json()
                        if "error" in error_data:
                            error_msg += f" - {error_data['error'].get('message', '')}"
                    except:
                        pass
                    raise Exception(error_msg)
            
            except (requests.ConnectionError, requests.Timeout) as e:
                # 网络错误，重试
                if attempt < self.max_retries - 1:
                    wait_time = self.retry_delay * (2 ** attempt)  # 指数退避
                    print(f"网络错误: {e}. 等待 {wait_time} 秒后重试...")
                    time.sleep(wait_time)
                else:
                    if isinstance(e, requests.ConnectionError):
                        raise ConnectionError(f"网络连接错误: {e}")
                    else:
                        raise TimeoutError(f"请求超时: {e}")
                        
            except Exception as e:
                # 其他未预期的错误
                raise Exception(f"请求时出现错误: {e}")
        
        # 所有重试都失败
        raise Exception("达到最大重试次数，请求失败")
    
    def _format_messages(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        格式化消息以适应 OpenAI API 格式
        
        Args:
            messages: 原始消息列表
            
        Returns:
            格式化后的消息列表
        """
        formatted_messages = []
        
        for message in messages:
            role = message.get("role", "user")
            content = message.get("content", [])
            
            # 处理复杂内容（如包含文本和图像的内容）
            if isinstance(content, list):
                formatted_content = []
                
                for item in content:
                    item_type = item.get("type")
                    
                    if item_type == "text":
                        formatted_content.append({
                            "type": "text",
                            "text": item.get("text", "")
                        })
                    elif item_type == "image_url":
                        # 处理图像 URL
                        image_url = item.get("image_url", {}).get("url", "")
                        if image_url:
                            formatted_content.append({
                                "type": "image_url",
                                "image_url": {
                                    "url": image_url
                                }
                            })
                
                formatted_messages.append({
                    "role": role,
                    "content": formatted_content
                })
            else:
                # 简单文本内容
                formatted_messages.append({
                    "role": role,
                    "content": content
                })
        
        return formatted_messages 