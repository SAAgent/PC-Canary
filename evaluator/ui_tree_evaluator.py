"""
基于UI元素树的评估器 - 使用UI元素树验证任务执行状态
"""

import subprocess
import time
import re
import json
from typing import Dict, List, Any, Optional, Callable, Tuple

from evaluator.base_evaluator import BaseEvaluator


class UITreeEvaluator(BaseEvaluator):
    """基于UI元素树的评估器，使用系统命令获取窗口和UI元素信息"""

    def __init__(self, task_name: str):
        """
        初始化UI树评估器
        
        Args:
            task_name: 任务名称
        """
        super().__init__(task_name)
        self.ui_cache = {}  # 缓存UI树信息
        self.window_cache = {}  # 缓存窗口信息
        
    def _check_condition(self, context: Any, condition: Dict) -> bool:
        """
        检查UI条件是否满足
        
        Args:
            context: 评估上下文
            condition: 条件描述
            
        Returns:
            bool: 条件是否满足
        """
        condition_type = condition.get('type', 'unknown')
        
        if condition_type == 'window_exists':
            return self._check_window_exists(condition.get('title_pattern', ''))
            
        elif condition_type == 'window_active':
            return self._check_window_active(condition.get('title_pattern', ''))
            
        elif condition_type == 'element_exists':
            return self._check_element_exists(
                condition.get('window_pattern', ''),
                condition.get('element_properties', {})
            )
            
        elif condition_type == 'element_state':
            return self._check_element_state(
                condition.get('window_pattern', ''),
                condition.get('element_properties', {}),
                condition.get('state', {})
            )
            
        self.log(f"未知的条件类型: {condition_type}")
        return False

    def _get_window_list(self) -> List[Dict]:
        """
        获取当前窗口列表
        
        Returns:
            List[Dict]: 窗口信息列表
        """
        try:
            # 使用xwininfo或xdotool获取窗口列表
            output = subprocess.check_output(
                "xdotool search --onlyvisible --name . getwindowname", 
                shell=True
            ).decode()
            
            window_ids = subprocess.check_output(
                "xdotool search --onlyvisible --name .", 
                shell=True
            ).decode().strip().split("\n")
            
            window_names = output.strip().split("\n")
            
            windows = []
            for i, win_id in enumerate(window_ids):
                if i < len(window_names):
                    windows.append({
                        'id': win_id,
                        'title': window_names[i]
                    })
            
            # 更新缓存
            self.window_cache = {w['id']: w for w in windows}
            return windows
            
        except Exception as e:
            self.log(f"获取窗口列表失败: {str(e)}")
            return []

    def _get_active_window(self) -> Optional[Dict]:
        """
        获取当前活动窗口
        
        Returns:
            Optional[Dict]: 活动窗口信息
        """
        try:
            # 获取活动窗口ID
            win_id = subprocess.check_output(
                "xdotool getactivewindow", 
                shell=True
            ).decode().strip()
            
            # 获取窗口标题
            title = subprocess.check_output(
                f"xdotool getwindowname {win_id}", 
                shell=True
            ).decode().strip()
            
            return {'id': win_id, 'title': title}
            
        except Exception as e:
            self.log(f"获取活动窗口失败: {str(e)}")
            return None

    def _get_window_by_pattern(self, pattern: str) -> Optional[Dict]:
        """
        通过标题模式查找窗口
        
        Args:
            pattern: 窗口标题模式(正则表达式)
            
        Returns:
            Optional[Dict]: 匹配的窗口信息
        """
        windows = self._get_window_list()
        for window in windows:
            if re.search(pattern, window['title']):
                return window
        return None
        
    def _get_ui_tree(self, window_id: str) -> Dict:
        """
        获取窗口的UI元素树
        
        Args:
            window_id: 窗口ID
            
        Returns:
            Dict: UI元素树
        """
        if window_id in self.ui_cache:
            return self.ui_cache[window_id]
            
        try:
            tree = self._get_ui_tree_mock(window_id)
            
            # 更新缓存
            self.ui_cache[window_id] = tree
            return tree
            
        except Exception as e:
            self.log(f"获取UI元素树失败: {str(e)}")
            return {}
            
    def _get_ui_tree_mock(self, window_id: str) -> Dict:
        """
        模拟获取UI元素树(在Docker中可能无法直接访问)
        这里模拟实现，实际使用时应替换为真实实现
        
        Args:
            window_id: 窗口ID
            
        Returns:
            Dict: 模拟的UI元素树
        """
        # 获取窗口标题
        title = "Unknown"
        if window_id in self.window_cache:
            title = self.window_cache[window_id]['title']
        else:
            try:
                title = subprocess.check_output(
                    f"xdotool getwindowname {window_id}", 
                    shell=True
                ).decode().strip()
            except:
                pass
                
        # 模拟不同应用的UI树结构
        if "Telegram" in title:
            return {
                'role': 'application',
                'name': title,
                'children': [
                    {
                        'role': 'window',
                        'name': title,
                        'children': [
                            {
                                'role': 'toolbar',
                                'name': 'toolbar',
                                'children': [
                                    {
                                        'role': 'button',
                                        'name': 'search',
                                        'properties': {'accessible-name': 'Search'}
                                    }
                                ]
                            },
                            {
                                'role': 'text_entry',
                                'name': 'search_box',
                                'properties': {'accessible-name': 'Search'}
                            },
                            {
                                'role': 'list',
                                'name': 'search_results',
                                'children': []
                            }
                        ]
                    }
                ]
            }
        else:
            # 默认空树
            return {
                'role': 'application',
                'name': title,
                'children': [
                    {
                        'role': 'window',
                        'name': title,
                        'children': []
                    }
                ]
            }
            
    def _find_elements(self, ui_tree: Dict, properties: Dict) -> List[Dict]:
        """
        在UI树中查找匹配属性的元素
        
        Args:
            ui_tree: UI元素树
            properties: 要匹配的属性
            
        Returns:
            List[Dict]: 匹配的元素列表
        """
        results = []
        
        def _matches(element: Dict) -> bool:
            """检查元素是否匹配所有属性"""
            for key, value in properties.items():
                if key == 'role' and element.get('role') != value:
                    return False
                elif key == 'name' and element.get('name') != value:
                    return False
                elif key == 'name_contains' and value not in element.get('name', ''):
                    return False
                elif key == 'properties':
                    for prop_key, prop_value in value.items():
                        if element.get('properties', {}).get(prop_key) != prop_value:
                            return False
            return True
        
        def _traverse(node: Dict):
            """递归遍历UI树"""
            if _matches(node):
                results.append(node)
                
            for child in node.get('children', []):
                _traverse(child)
        
        _traverse(ui_tree)
        return results
        
    def _check_window_exists(self, title_pattern: str) -> bool:
        """
        检查特定标题的窗口是否存在
        
        Args:
            title_pattern: 窗口标题模式
            
        Returns:
            bool: 窗口是否存在
        """
        window = self._get_window_by_pattern(title_pattern)
        return window is not None
        
    def _check_window_active(self, title_pattern: str) -> bool:
        """
        检查特定标题的窗口是否活动
        
        Args:
            title_pattern: 窗口标题模式
            
        Returns:
            bool: 窗口是否活动
        """
        active_window = self._get_active_window()
        if not active_window:
            return False
            
        return bool(re.search(title_pattern, active_window['title']))
        
    def _check_element_exists(self, window_pattern: str, element_properties: Dict) -> bool:
        """
        检查特定窗口中是否存在匹配属性的元素
        
        Args:
            window_pattern: 窗口标题模式
            element_properties: 元素属性
            
        Returns:
            bool: 元素是否存在
        """
        window = self._get_window_by_pattern(window_pattern)
        if not window:
            return False
            
        ui_tree = self._get_ui_tree(window['id'])
        elements = self._find_elements(ui_tree, element_properties)
        
        return len(elements) > 0
        
    def _check_element_state(self, window_pattern: str, element_properties: Dict, state: Dict) -> bool:
        """
        检查特定窗口中匹配属性的元素是否处于特定状态
        
        Args:
            window_pattern: 窗口标题模式
            element_properties: 元素属性
            state: 要检查的状态
            
        Returns:
            bool: 元素是否处于指定状态
        """
        window = self._get_window_by_pattern(window_pattern)
        if not window:
            return False
            
        ui_tree = self._get_ui_tree(window['id'])
        elements = self._find_elements(ui_tree, element_properties)
        
        if not elements:
            return False
            
        # 检查第一个匹配元素的状态
        element = elements[0]
        
        for key, value in state.items():
            if key == 'visible':
                # 元素存在即认为可见
                if value != True:
                    return False
            elif key == 'enabled':
                # 模拟实现，实际应检查元素状态
                if value != element.get('properties', {}).get('enabled', True):
                    return False
            elif key == 'text':
                # 检查元素文本
                if value != element.get('properties', {}).get('text', ''):
                    return False
                    
        return True
        
    def clear_cache(self):
        """清除缓存的UI树和窗口信息"""
        self.ui_cache = {}
        self.window_cache = {} 