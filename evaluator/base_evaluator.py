"""
基础评估器类 - 定义评估器的通用接口和方法
"""

import time
import json
import os
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Callable, Optional, Tuple


class BaseEvaluator(ABC):
    """评估器基类，定义评估过程的基本流程和接口"""

    def __init__(self, task_name: str):
        """
        初始化评估器
        
        Args:
            task_name: 任务名称
        """
        self.task_name = task_name
        self.steps = []  # 步骤列表
        self.results = {}  # 评估结果
        self.start_time = None  # 任务开始时间
        self.end_time = None  # 任务结束时间
        self.log_path = f"evaluator/logs/{task_name}_{int(time.time())}.json"
        
        # 确保日志目录存在
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
    
    def register_step(self, step_name: str, description: str, 
                     check_func: Callable, timeout: int = 30,
                     metadata: Optional[Dict] = None) -> None:
        """
        注册评估步骤
        
        Args:
            step_name: 步骤唯一标识
            description: 步骤描述
            check_func: 检查步骤是否完成的函数
            timeout: 步骤超时时间(秒)
            metadata: 步骤相关的元数据
        """
        self.steps.append({
            'name': step_name,
            'description': description,
            'check': check_func,
            'timeout': timeout,
            'metadata': metadata or {}
        })
        
    def start_evaluation(self) -> None:
        """开始评估任务"""
        self.start_time = time.time()
        self.results = {}
        self.log(f"开始评估任务: {self.task_name}")
        
    def end_evaluation(self) -> None:
        """结束评估任务"""
        self.end_time = time.time()
        self.log(f"评估任务完成: {self.task_name}")
        
    def evaluate_step(self, step_name: str, context: Any = None) -> bool:
        """
        评估特定步骤
        
        Args:
            step_name: 步骤名称
            context: 评估上下文信息(如截图、状态等)
            
        Returns:
            bool: 步骤是否成功
        """
        step = next((s for s in self.steps if s['name'] == step_name), None)
        if not step:
            self.log(f"未找到步骤: {step_name}")
            return False
            
        start_time = time.time()
        try:
            success = step['check'](context)
        except Exception as e:
            self.log(f"步骤 {step_name} 评估出错: {str(e)}")
            success = False
            
        duration = time.time() - start_time
            
        self.results[step_name] = {
            'success': success,
            'duration': duration,
            'timestamp': time.time()
        }
        
        self.log(f"步骤 '{step['description']}': {'成功' if success else '失败'} ({duration:.2f}s)")
        return success
    
    def evaluate_all(self, context_provider: Callable = None) -> Dict:
        """
        评估所有注册的步骤
        
        Args:
            context_provider: 提供评估上下文的函数
            
        Returns:
            Dict: 评估报告
        """
        self.start_evaluation()
        
        for step in self.steps:
            context = context_provider() if context_provider else None
            success = self.evaluate_step(step['name'], context)
            
            # 如果步骤失败，可以决定是否继续
            if not success and not self.should_continue_after_failure(step['name']):
                self.log(f"步骤 {step['name']} 失败，终止评估")
                break
        
        self.end_evaluation()
        return self.generate_report()
        
    def should_continue_after_failure(self, step_name: str) -> bool:
        """
        决定步骤失败后是否继续评估
        
        Args:
            step_name: 失败的步骤名称
            
        Returns:
            bool: 是否继续评估
        """
        # 默认继续评估，子类可重写此方法实现自定义逻辑
        return True
        
    def generate_report(self) -> Dict:
        """
        生成评估报告
        
        Returns:
            Dict: 评估报告
        """
        if not self.end_time:
            self.end_time = time.time()
            
        total_time = self.end_time - self.start_time
        success_count = sum(1 for r in self.results.values() if r.get('success', False))
        total_steps = len(self.steps)
        success_rate = success_count / total_steps if total_steps else 0
        
        report = {
            "task_name": self.task_name,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "total_time": total_time,
            "success_rate": success_rate,
            "steps_completed": success_count,
            "total_steps": total_steps,
            "detailed_results": self.results
        }
        
        # 保存评估报告
        self.save_report(report)
        
        self.log(f"评估完成：成功率 {success_rate*100:.1f}%, 总耗时 {total_time:.1f}秒")
        return report
    
    def save_report(self, report: Dict) -> None:
        """
        保存评估报告到文件
        
        Args:
            report: 评估报告
        """
        try:
            with open(self.log_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            self.log(f"评估报告已保存至: {self.log_path}")
        except Exception as e:
            self.log(f"保存评估报告失败: {str(e)}")
    
    def log(self, message: str) -> None:
        """
        记录日志
        
        Args:
            message: 日志信息
        """
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        print(f"[{timestamp}] [Evaluator] {message}")
    
    @abstractmethod
    def _check_condition(self, context: Any, condition: Any) -> bool:
        """
        检查条件是否满足，子类必须实现此方法
        
        Args:
            context: 评估上下文
            condition: 条件
            
        Returns:
            bool: 条件是否满足
        """
        pass 