#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import time
from typing import Dict, Any, Optional, List
from PIL import Image

save_path = None
screenshot_called = False
screenshot_success = False

def verify_screenshot_path(save_path: str, logger, task_parameter) -> List[Dict[str, Any]]:
    """验证截图保存路径是否符合要求"""
    try:
        expected_path = task_parameter["save_path"]
        print(os.path.dirname(save_path))
        print(expected_path)
        # 检查路径是否匹配
        if expected_path.rstrip("/") != os.path.dirname(save_path):
            logger.error(f"截图保存路径不匹配: 期望 {expected_path}, 实际 {save_path}")
            return [
                {"status": "error", "message": f"截图保存路径不匹配: 期望 {expected_path}, 实际 {save_path}"}
            ]
            
        # 检查文件是否存在
        if not os.path.exists(save_path):
            logger.error(f"截图文件不存在: {save_path}")
            return [
                {"status": "error", "message": f"截图文件不存在: {save_path}"}
            ]
            
        return [
            {"status": "key_step", "index": 1}
        ]
    except Exception as e:
        logger.error(f"验证截图路径时发生错误: {e}")
        return [
            {"status": "error", "message": f"验证截图路径时发生错误: {e}"}
        ]

def verify_screenshot_size(save_path: str, logger, task_parameter) -> List[Dict[str, Any]]:
    """验证截图尺寸是否符合要求"""
    try:
        with Image.open(save_path) as img:
            width, height = img.size
            expected_width = task_parameter["width"]
            expected_height = task_parameter["height"]
            
            if width != expected_width or height != expected_height:
                logger.error(
                    f"截图尺寸不匹配: 期望 {expected_width}x{expected_height}, "
                    f"实际 {width}x{height}"
                )
                return [
                    {"status": "error", "message": f"截图尺寸不匹配: 期望 {expected_width}x{expected_height}, 实际 {width}x{height}"}
                ]
                
            return [
                {"status": "key_step", "index": 2},
                {"status": "success", "reason": "截图路径和尺寸都匹配成功"},
            ]
    except Exception as e:
        logger.error(f"验证截图尺寸时发生错误: {e}")
        return [
            {"status": "error", "message": f"验证截图尺寸时发生错误: {e}"}
        ]

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    global save_path, screenshot_called, screenshot_success
    payload = message['payload']
    print(payload)
    event = payload['event']
    logger.debug(f"接收到事件: {event}")
    key_step = []
    
    # 处理函数调用事件
    if event == "function called" and payload.get("function") == "OBSBasic::Screenshot":
        screenshot_called = True
        logger.info("检测到截图函数调用")
        return None

    # 处理函数返回事件
    if event == "function returned" and payload.get("function") == "OBSBasic::Screenshot":
        screenshot_success = payload.get("success", False)
        if not screenshot_success:
            logger.error("截图函数执行失败")
        return None

    # 处理获取保存路径事件
    if event == "screenshot_getpath":
        save_path = payload.get("save_path")
        if not save_path:
            logger.error("未获取到截图保存路径")
            return None
        logger.info(f"获取到截图保存路径: {save_path}")
        
    # 处理错误事件
    if event == "screenshot_error":
        error_msg = payload.get("message", "未知错误")
        error_detail = payload.get("error", "无详细信息")
        logger.error(f"截图过程发生错误: {error_msg}, 详细信息: {error_detail}")
        return [
            {"status": "error", "message": f"{error_msg}"}
        ]
        
    # 处理截图保存成功事件
    if event == "screenshot_saved":
        if not screenshot_called:
            logger.error("未检测到截图函数调用")
            return None
            
        if not screenshot_success:
            logger.error("截图函数执行失败")
            return None
            
        if not save_path:
            logger.error("未获取到截图保存路径")
            return None
            
        # 验证截图路径和尺寸
        key_step.extend(verify_screenshot_path(save_path, logger, task_parameter)) 
        key_step.extend(verify_screenshot_size(save_path, logger, task_parameter))

        return key_step
    
    if event == "RequestHandlerSaveScreenshot_returned":
        # 检查 config.json 中设置的 save_path 文件夹下是否有符合条件的 .png 文件
        config_save_path = task_parameter.get("save_path")
        if not config_save_path:
            logger.error("未在配置中找到 save_path")
            return [
            {"status": "error", "message": "未在配置中找到 save_path"}
            ]
        
        try:
            file_path = config_save_path
            if not os.path.exists(file_path):
                logger.error(f"文件 {file_path} 不存在")
                return [
                    {"status": "error", "message": f"文件 {file_path} 不存在"}
                ]
            
            with Image.open(file_path) as img:
                width, height = img.size
                expected_width = task_parameter["width"]
                expected_height = task_parameter["height"]
                
                if width != expected_width or height != expected_height:
                    logger.error(
                        f"文件 {file_path} 的分辨率不匹配: "
                        f"期望 {expected_width}x{expected_height}, 实际 {width}x{height}"
                    )
                    return [
                        {"status": "error", "message": f"文件 {file_path} 的分辨率不匹配: 期望 {expected_width}x{expected_height}, 实际 {width}x{height}"}
                    ]
            
            logger.info(f"文件 {file_path} 验证成功")
            return [
                {"status": "key_step", "index": 1},
                {"status": "key_step", "index": 2},
                {"status": "success", "message": f"文件 {file_path} 验证成功"}
            ]
        except Exception as e:
            logger.error(f"检查文件时发生错误: {e}")
            return [
                {"status": "error", "message": f"检查文件时发生错误: {e}"}
            ]

    return None
