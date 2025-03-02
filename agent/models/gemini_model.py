"""
Google Gemini 模型接口

提供与 Google Generative AI API 交互的统一接口
"""

import os
from typing import List, Dict, Any, Optional, Union
import time

from .base_model import BaseModel

try:
    # 尝试导入 Google Generative AI 库
    import google.generativeai as genai
    from google.generativeai.types import generation_types
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False


class GeminiModelResponse:
    """
    Gemini 模型响应封装
    """
    
    def __init__(self, response_data):
        """
        初始化响应对象
        
        Args:
            response_data: API 响应数据
        """
        self.response_data = response_data
        self.text = self._extract_content()
    
    def _extract_content(self):
        """从响应中提取文本内容"""
        try:
            # 处理不同类型的响应对象
            if hasattr(self.response_data, "text"):
                # 如果是 GenerateContentResponse 对象
                return self.response_data.text
            elif hasattr(self.response_data, "parts"):
                # 如果是消息对象
                parts = self.response_data.parts
                if parts and hasattr(parts[0], "text"):
                    return parts[0].text
            
            # 如果是字典或其他类型
            if isinstance(self.response_data, dict):
                return self.response_data.get("text", "")
            
            # 如果都不是，尝试转换为字符串
            return str(self.response_data)
        except Exception as e:
            print(f"提取响应内容时出错: {e}")
            return ""
    
    def __str__(self):
        return self.text


class GeminiModel(BaseModel):
    """
    Google Gemini 模型接口
    
    提供与 Google Generative AI API 交互的方法
    """
    
    def __init__(self, 
                 api_key: str, 
                 model_name: str = "gemini-1.5-pro", 
                 max_retries: int = 3,
                 retry_delay: float = 1.0,
                 temperature: float = 0.7,
                 top_p: float = 0.95,
                 top_k: int = 40,
                 max_output_tokens: Optional[int] = None,
                 system_instruction: Optional[str] = None,
                 **kwargs):
        """
        初始化 Gemini 模型
        
        Args:
            api_key: Google API 密钥
            model_name: 模型名称，默认为 "gemini-1.5-pro"
            max_retries: 最大重试次数
            retry_delay: 重试间隔（秒）
            temperature: 温度参数，控制随机性
            top_p: 控制生成多样性
            top_k: 控制生成多样性
            max_output_tokens: 最大生成令牌数
            system_instruction: 系统指令
            **kwargs: 其他参数
        """
        super().__init__(api_key=api_key, model_name=model_name, **kwargs)
        
        if not GENAI_AVAILABLE:
            raise ImportError("未安装 Google Generative AI 库. 请运行 'pip install google-generativeai'")
        
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.system_instruction = system_instruction
        
        # 初始化 Google Generative AI
        genai.configure(api_key=api_key)
        
        # 配置生成参数
        self.generation_config = {
            "temperature": temperature,
            "top_p": top_p,
            "top_k": top_k,
        }
        
        if max_output_tokens:
            self.generation_config["max_output_tokens"] = max_output_tokens
        
        # 创建模型实例
        try:
            self.model = genai.GenerativeModel(
                model_name=model_name,
                generation_config=self.generation_config,
                system_instruction=system_instruction
            )
        except Exception as e:
            raise ValueError(f"初始化 Gemini 模型失败: {e}")
    
    def generate_content(self, messages: List[Dict[str, Any]]) -> GeminiModelResponse:
        """
        生成内容
        
        Args:
            messages: 消息列表，包含对话历史
            
        Returns:
            GeminiModelResponse 对象
        
        Raises:
            ValueError: API 密钥无效或其他参数错误
            ConnectionError: 网络连接错误
            TimeoutError: 请求超时
            Exception: 其他错误
        """
        self._validate_api_key()
        
        # 构建请求
        try:
            # 使用 Gemini 的 GenerativeModel 直接传递消息
            for attempt in range(self.max_retries):
                try:
                    response = self.model.generate_content(messages)
                    return GeminiModelResponse(response)
                
                except generation_types.BlockedPromptException as e:
                    # 提示被阻止
                    raise ValueError(f"提示被阻止: {e}")
                
                except generation_types.StopCandidateException as e:
                    # 候选回答被停止
                    raise ValueError(f"候选回答被停止: {e}")
                
                except Exception as e:
                    # 其他错误，尝试重试
                    if "429" in str(e) or "rate limit" in str(e).lower():
                        # 速率限制
                        wait_time = self.retry_delay * (2 ** attempt)  # 指数退避
                        print(f"速率限制错误: {e}. 等待 {wait_time} 秒后重试...")
                        time.sleep(wait_time)
                        if attempt == self.max_retries - 1:
                            raise Exception(f"达到最大重试次数，请求失败: {e}")
                    else:
                        # 其他错误，不重试
                        raise Exception(f"生成内容时出错: {e}")
            
        except Exception as e:
            raise Exception(f"请求 Gemini API 时出错: {e}")
    
    def _format_messages(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Gemini API 已经支持直接处理消息列表，不需要特殊格式化
        实际上在 generate_content 中直接使用了原始消息
        """
        return messages 