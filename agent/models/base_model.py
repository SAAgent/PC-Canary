"""
基础模型接口

定义所有模型接口必须实现的方法
"""

class BaseModel:
    """
    模型接口基类
    
    定义所有模型必须实现的方法
    """
    
    def __init__(self, api_key=None, model_name=None, **kwargs):
        """
        初始化模型
        
        Args:
            api_key: API 密钥
            model_name: 模型名称
            **kwargs: 其他参数
        """
        self.api_key = api_key
        self.model_name = model_name
        self.kwargs = kwargs
    
    def generate_content(self, messages):
        """
        生成内容
        
        Args:
            messages: 消息列表，包含对话历史
            
        Returns:
            响应对象，包含生成的文本
        """
        raise NotImplementedError("子类必须实现 generate_content 方法")
    
    def _validate_api_key(self):
        """验证 API 密钥是否有效"""
        if not self.api_key:
            raise ValueError("API 密钥不能为空")
        
    def _format_messages(self, messages):
        """
        格式化消息，子类可能需要重写该方法以适应不同 API 的格式要求
        
        Args:
            messages: 消息列表
            
        Returns:
            格式化后的消息
        """
        return messages 