#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OBS导出场景截图操作
负责处理钩子脚本产生的事件并更新评估指标
"""

import os
import json
import time
from typing import Dict, Any, Optional
from PIL import Image

_EVALUATOR = None
_CONFIG = None
_START_TIME = None
save_path = None
screenshot_called = False
screenshot_success = False

def set_evaluator(evaluator):
    """设置全局评估器实例"""
    global _EVALUATOR, _CONFIG
    _EVALUATOR = evaluator

    # 使用评估器的已更新配置，而不是重新读取文件
    if hasattr(evaluator, "config") and evaluator.config:
        _CONFIG = evaluator.config
        _EVALUATOR.logger.info("使用评估器中的更新配置")
    else:
        # 作为备份，如果评估器中没有配置，才从文件读取
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            config_file = os.path.join(current_dir, "config.json")

            with open(config_file, "r") as f:
                _CONFIG = json.load(f)
                _EVALUATOR.logger.info("从文件加载配置")
        except Exception as e:
            _EVALUATOR.logger.error(f"加载配置文件失败: {e}")
            return

def verify_screenshot_path(save_path: str) -> bool:
    """验证截图保存路径是否符合要求"""
    try:
        expected_path = _CONFIG["task_parameters"]["save_path"]
        print(os.path.dirname(save_path))
        print(expected_path)
        # 检查路径是否匹配
        if expected_path.rstrip("/") != os.path.dirname(save_path):
            _EVALUATOR.logger.error(f"截图保存路径不匹配: 期望 {expected_path}, 实际 {save_path}")
            return False
            
        # 检查文件是否存在
        if not os.path.exists(save_path):
            _EVALUATOR.logger.error(f"截图文件不存在: {save_path}")
            return False
            
        return True
    except Exception as e:
        _EVALUATOR.logger.error(f"验证截图路径时发生错误: {e}")
        return False

def verify_screenshot_size(save_path: str) -> bool:
    """验证截图尺寸是否符合要求"""
    try:
        with Image.open(save_path) as img:
            width, height = img.size
            expected_width = _CONFIG["task_parameters"]["width"]
            expected_height = _CONFIG["task_parameters"]["height"]
            
            if width != expected_width or height != expected_height:
                _EVALUATOR.logger.error(
                    f"截图尺寸不匹配: 期望 {expected_width}x{expected_height}, "
                    f"实际 {width}x{height}"
                )
                return False
                
            return True
    except Exception as e:
        _EVALUATOR.logger.error(f"验证截图尺寸时发生错误: {e}")
        return False

def message_handler(message: Dict[str, Any], data: Any) -> Optional[str]:
    """处理来自钩子脚本的消息"""
    global _START_TIME, save_path, screenshot_called, screenshot_success
    
    if not _EVALUATOR or not _CONFIG:
        return None
        
    message = message['payload']
    event = message.get("event")
    if not event:
        return None
        
    # 记录开始时间
    if event == "script_initialized":
        _START_TIME = time.time()
        _EVALUATOR.logger.info("开始监控OBS截图操作")
        return None

    # 处理函数调用事件
    if event == "function called" and message.get("function") == "OBSBasic::Screenshot":
        screenshot_called = True
        _EVALUATOR.logger.info("检测到截图函数调用")
        return None

    # 处理函数返回事件
    if event == "function returned" and message.get("function") == "OBSBasic::Screenshot":
        screenshot_success = message.get("success", False)
        if not screenshot_success:
            _EVALUATOR.logger.error("截图函数执行失败")
        return None
    
    # 处理获取保存路径事件
    if event == "screenshot_getpath":
        save_path = message.get("save_path")
        if not save_path:
            _EVALUATOR.logger.error("未获取到截图保存路径")
            return None
        _EVALUATOR.logger.info(f"获取到截图保存路径: {save_path}")
        
    # 处理错误事件
    if event == "screenshot_error":
        error_msg = message.get("message", "未知错误")
        error_detail = message.get("error", "无详细信息")
        _EVALUATOR.logger.error(f"截图过程发生错误: {error_msg}, 详细信息: {error_detail}")
        return None
        
    # 处理截图保存成功事件
    if event == "screenshot_saved":
        if not screenshot_called:
            _EVALUATOR.logger.error("未检测到截图函数调用")
            return None
            
        if not screenshot_success:
            _EVALUATOR.logger.error("截图函数执行失败")
            return None
            
        if not save_path:
            _EVALUATOR.logger.error("未获取到截图保存路径")
            return None
            
        # 验证截图路径和尺寸
        if verify_screenshot_path(save_path) and verify_screenshot_size(save_path):
            completion_time = time.time() - _START_TIME
            _EVALUATOR.update_metric("screenshot_saved", True)
            _EVALUATOR.update_metric("save_path", save_path)
            _EVALUATOR.update_metric("duration", completion_time)
            _EVALUATOR.logger.info(f"截图保存成功，耗时: {completion_time:.2f}秒")
            return "success"
        else:
            _EVALUATOR.update_metric("screenshot_saved", False)
            _EVALUATOR.logger.error("截图验证失败")
            return None

    return None

def register_handlers(evaluator):
    """注册消息处理函数"""
    set_evaluator(evaluator)
    return message_handler 