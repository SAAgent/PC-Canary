"""
OpenAI 模型接口

提供与 OpenAI API 交互的统一接口
"""

from typing import List, Dict, Any, Optional, Union
import time
import json

# 导入官方的 OpenAI 库
from openai import OpenAI
from openai.types.chat import ChatCompletion

from .base_model import BaseModel


class OpenAIModel(BaseModel):
    """
    OpenAI 模型接口
    
    提供与 OpenAI API 交互的方法，使用官方 OpenAI 库
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
        
        # 初始化 OpenAI 客户端
        self.client = OpenAI(
            api_key=api_key,
            base_url=api_base,
            max_retries=max_retries,
            timeout=60.0
        )
    
    def generate_content(self, messages: List[Dict[str, Any]]):
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
        # formatted_messages = self._format_messages(messages)
        
        # 构建请求参数
        completion_params = {
            "model": self.model_name,
            "messages": messages,
            "temperature": self.temperature,
            "top_p": self.top_p,
        }
        
        if self.max_tokens:
            completion_params["max_tokens"] = self.max_tokens
        
        # 使用指数退避的重试机制
        for attempt in range(self.max_retries):
            try:
                # 使用官方 API 客户端发送请求
                response = self.client.chat.completions.create(**completion_params)
                return response
                
            except Exception as e:
                error_msg = str(e)
                
                # 处理速率限制错误
                if "rate limit" in error_msg.lower() or "429" in error_msg:
                    if attempt < self.max_retries - 1:
                        wait_time = self.retry_delay * (2 ** attempt)  # 指数退避
                        print(f"触发速率限制，等待 {wait_time} 秒后重试...")
                        time.sleep(wait_time)
                        continue
                    else:
                        raise Exception(f"达到最大重试次数，速率限制错误: {e}")
                
                # 处理连接错误
                elif "connection" in error_msg.lower() or "timeout" in error_msg.lower():
                    if attempt < self.max_retries - 1:
                        wait_time = self.retry_delay * (2 ** attempt)  # 指数退避
                        print(f"网络错误: {e}. 等待 {wait_time} 秒后重试...")
                        time.sleep(wait_time)
                        continue
                    else:
                        if "timeout" in error_msg.lower():
                            raise TimeoutError(f"请求超时: {e}")
                        else:
                            raise ConnectionError(f"网络连接错误: {e}")
                
                # 其他错误，直接抛出
                else:
                    raise Exception(f"请求时出现错误: {e}")
        
        # 所有重试都失败
        raise Exception("达到最大重试次数，请求失败")