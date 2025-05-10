#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FreeCAD事件处理器
负责处理钩子脚本产生的事件并判断任务是否完成
"""

from typing import Dict, Any, Optional, List

# 事件类型常量
SCRIPT_INITIALIZED = "script_initialized"
FUNCTION_NOT_FOUND = "function_not_found"
FUNCTION_FOUND = "function_found"
FUNCTION_CALLED = "function_called"
FUNCTION_KEY_WORD_DETECTED = "function_key_word_detected"
ERROR = "error"
HOOK_INSTALLED = "hook_installed"

# 关键字相关常量
LENGTH = "length"
FOUND = "found"
HAS_LINE = "has_line"

def execute_python_code(code: str, logger: Any) -> Dict[str, Any]:
    """
    执行Python代码并返回结果
    
    Args:
        code: 要执行的Python代码
        logger: 日志记录器
        
    Returns:
        Dict[str, Any]: 执行结果
    """
    try:
        # 创建一个新的命名空间来执行代码
        namespace = {}
        exec(code, namespace)
        result = namespace.get('result', None)
        
        if result is None:
            logger.warning("未找到直线对象")
            return None
            
        return result
    except Exception as e:
        logger.error(f"执行Python代码时出错: {str(e)}")
        return None

def message_handler(message: Dict[str, Any], logger: Any, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """
    处理从钩子脚本接收的消息
    
    Args:
        message: Frida消息对象
        logger: 日志记录器
        task_parameter: 任务参数
        
    Returns:
        List[Dict[str, Any]]: 包含状态更新的字典列表，如果没有状态更新则返回None
    """
    updates = []
    
    # 处理消息
    if message.get('type') == 'send' and 'payload' in message:
        payload = message['payload']
        
        # 检查是否包含事件类型
        if 'event' in payload:
            event_type = payload['event']
            logger.debug(f"接收到事件: {event_type}")
            
            # 处理特定事件
            if event_type == SCRIPT_INITIALIZED:
                logger.info(f"钩子脚本初始化: {payload.get('message', '')}")
                
            elif event_type == FUNCTION_FOUND:
                logger.info(f"找到函数: {payload.get('address', '')}")
                
            elif event_type == FUNCTION_CALLED:
                logger.info(f"函数被调用: {payload.get('message', '')}")
                # 保存文档是第一个关键步骤
                updates.append({
                    'status': 'key_step',
                    'index': 1,
                    'name': '保存文档'
                })
                
            elif event_type == FUNCTION_KEY_WORD_DETECTED:
                # 执行Python代码并获取结果
                code = payload.get('code', '')
                filename = payload.get('filename', '')
                logger.info(f"检测到关键字，文档路径: {filename}")
                
                result = execute_python_code(code, logger)
                if result:
                    # 检查草图是否创建并且有直线
                    if result.get(FOUND, False) and result.get(HAS_LINE, False):
                        # 检查直线长度是否符合要求
                        expected_length = task_parameter.get('line_length', 50.0)
                        actual_length = result.get(LENGTH, 0.0)
                        
                        # 验证长度是否符合要求
                        if abs(actual_length - expected_length) <= 0.00001:
                            logger.info(f"直线长度符合要求: 预期 {expected_length:.2f}, 实际 {actual_length:.2f}")
                            
                            # 更新第二个关键步骤状态 - 创建直线并保存成功
                            updates.append({
                                'status': 'key_step',
                                'index': 2,
                                'name': '创建直线并保存成功'
                            })
                            
                            # 报告任务成功
                            updates.append({
                                'status': 'success',
                                'reason': f'成功创建长度为{actual_length:.2f}的直线'
                            })
                            
                            logger.info("任务成功完成!")
                        else:
                            logger.error(f"直线长度不符合要求: 预期 {expected_length:.2f}, 实际 {actual_length:.2f}")
                            
                            updates.append({
                                'status': 'error',
                                'type': 'validation_failed',
                                'message': f'直线长度不符合要求：期望{expected_length:.2f}，实际{actual_length:.2f}'
                            })
                    else:
                        if not result.get(FOUND, False):
                            logger.error("未找到草图对象")
                            updates.append({
                                'status': 'error',
                                'type': 'validation_failed',
                                'message': '未找到草图对象'
                            })
                        elif not result.get(HAS_LINE, False):
                            logger.error("草图中未找到直线")
                            updates.append({
                                'status': 'error',
                                'type': 'validation_failed',
                                'message': '草图中未找到直线'
                            })
                
            elif event_type == ERROR:
                error_type = payload.get("error_type", "unknown")
                error_message = payload.get("message", "未知错误")
                
                logger.error(f"钩子脚本错误 ({error_type}): {error_message}")
                
                updates.append({
                    'status': 'error',
                    'type': error_type,
                    'message': error_message
                })
                
    elif message.get('type') == 'error':
        logger.error(f"钩子脚本错误: {message.get('stack', '')}")
        
        updates.append({
            'status': 'error',
            'type': 'script_error',
            'message': message.get('stack', '未知错误')
        })
    
    return updates if updates else None