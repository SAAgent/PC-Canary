"""
模型接口模块

提供与不同 LLM API 交互的统一接口
"""

from .base_model import BaseModel
from .openai_model import OpenAIModel
from .gemini_model import GeminiModel

# 导出所有模型类
__all__ = ['BaseModel', 'OpenAIModel', 'GeminiModel'] 