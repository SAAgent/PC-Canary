from typing import Dict, Any, Optional
import os
import time
import json
import logging

class ResultCollector:
    """
    结果收集器，负责收集和保存评估结果
    """
    
    def __init__(self, output_dir: str = "results", logger: Optional[logging.Logger] = None):
        """
        初始化结果收集器
        
        Args:
            output_dir: 结果输出目录
            logger: 日志记录器，如果为None则使用默认记录器
        """
        self.output_dir = output_dir
        self.results = {}  # 任务ID -> 结果
        self.logger = logger
        
        os.makedirs(output_dir, exist_ok=True)
    
    def start_session(self, task_id: str, session_data: Dict[str, Any]) -> None:
        """
        开始一个评估会话
        
        Args:
            task_id: 任务ID
            session_data: 会话初始数据
        """
        if task_id not in self.results:
            self.results[task_id]['metrics'] = {
                "performance": {},
                "behavior": {},
                "correctness": {},
                "quality": {},
                "robustness": {}
            }
        now = time.time()
        self.results[task_id].update({
            "start_timestamp": now,
            **session_data
        })
        self.results[task_id].update(session_data)
        self.logger.info(f"任务会话开始: {task_id}")
    
    def end_session(self, task_id: str, session_data: Dict[str, Any]) -> None:
        """
        结束一个评估会话
        
        Args:
            task_id: 任务ID
            session_data: 会话结束数据
        """
        now = time.time()
        entry = self.results[task_id]
        entry.update(session_data)
        entry["end_timestamp"] = now
        entry["duration"] = now - entry.get("start_timestamp", now)
        if task_id in self.results:
            self.results[task_id].update(session_data)
            self.logger.info(f"任务会话结束: {task_id}")
    
    def add_event(self, task_id: str, event_data: Dict[str, Any]) -> None:
        """
        添加事件
        
        Args:
            task_id: 任务ID
            event_data: 事件数据
        """
        if task_id not in self.results:
            self.results[task_id] = {"events": [], "metrics": {}}
        
        self.results[task_id]["events"].append(event_data)
    
    def update_metrics(self, task_id: str, metrics: Dict[str, Any]) -> None:
        """
        更新评估指标
        
        Args:
            task_id: 任务ID
            metrics: 指标数据
        """
        if task_id not in self.results:
            self.results[task_id] = {"events": [], "metrics": {}}
        
        if "metrics" not in self.results[task_id]:
            self.results[task_id]["metrics"] = {}
        
        self.results[task_id]["metrics"].update(metrics)
    
    def get_results(self, task_id: Optional[str] = None) -> Dict[str, Any]:
        """
        获取评估结果
        
        Args:
            task_id: 任务ID，为None则返回所有结果
            
        Returns:
            Dict[str, Any]: 评估结果
        """
        if task_id is not None:
            return self.results.get(task_id, {})
        
        return self.results
    
    def save_results(self, task_id: Optional[str] = None) -> str:
        """
        保存评估结果到文件
        
        Args:
            task_id: 任务ID，为None则保存所有结果
            
        Returns:
            str: 结果文件路径
        """
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        
        if task_id is not None:
            # 保存单个任务结果
            if task_id not in self.results:
                self.logger.warning(f"任务结果不存在: {task_id}")
                return ""
            
            result_file = os.path.join(self.output_dir, f"{task_id}_{timestamp}.json")
            with open(result_file, 'w') as f:
                json.dump(self.results[task_id], f, indent=2)
            
            self.logger.info(f"任务结果已保存: {result_file}")
            return result_file
        else:
            # 保存所有任务结果
            result_file = os.path.join(self.output_dir, f"all_results_{timestamp}.json")
            with open(result_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            
            self.logger.info(f"所有结果已保存: {result_file}")
            return result_file
    
    def clear_results(self, task_id: Optional[str] = None) -> None:
        """
        清除评估结果
        
        Args:
            task_id: 任务ID，为None则清除所有结果
        """
        if task_id is not None:
            if task_id in self.results:
                del self.results[task_id]
                self.logger.info(f"清除任务结果: {task_id}")
        else:
            self.results = {}
            self.logger.info("清除所有评估结果")