#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FreeCAD正方形事件处理器
负责处理钩子脚本产生的事件并更新评估指标
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
SIDE_LENGTH = "side_length"
CENTER_X = "center_x"
CENTER_Y = "center_y"
HAS_SQUARE = "has_square"

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
            logger.warning("未找到正方形对象")
            return None
            
        # 验证结果格式
        required_keys = [SIDE_LENGTH, CENTER_X, CENTER_Y, HAS_SQUARE]
        if not all(key in result for key in required_keys):
            logger.error(f"结果缺少必要的键: {required_keys}")
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
        Optional[List[Dict[str, Any]]]: 状态更新列表，如果没有更新则为None
    """
    updates = []
    
    if message.get('type') == 'send' and 'payload' in message:
        payload = message['payload']
        
        if 'event' in payload:
            event_type = payload['event']
            logger.debug(f"接收到事件: {event_type}")
            
            if event_type == SCRIPT_INITIALIZED:
                logger.info(f"钩子脚本初始化: {payload.get('message', '')}")
                
            elif event_type == FUNCTION_FOUND:
                logger.info(f"找到函数: {payload.get('address', '')}")
                
            elif event_type == FUNCTION_CALLED:
                logger.info(f"函数被调用: {payload.get('message', '')}")
                # 更新第一个关键步骤状态
                updates.append({
                    'status': 'key_step',
                    'index': 1,
                    'name': '保存文档'
                })
                
            elif event_type == FUNCTION_KEY_WORD_DETECTED:
                # 执行Python代码并获取结果
                code = payload.get('code', '')
                filename = payload.get('filename', '')
                expected_path = task_parameter.get("source_path", "") + task_parameter.get("filename", "")
                logger.info(f"检测到关键字，文档路径: {filename}, 预期文档路径: {expected_path}")
                
                if filename == expected_path:
                    result = execute_python_code(code, logger)
                    if result:
                        # 检查正方形参数是否符合预期
                        expected_side_length = task_parameter.get(SIDE_LENGTH, 10)
                        
                        actual_side_length = result[SIDE_LENGTH]
                        actual_center_x = result[CENTER_X]
                        actual_center_y = result[CENTER_Y]
                        has_square = result[HAS_SQUARE]

                        # 日志记录关键参数
                        logger.info(f"任务参数检查: 期望边长 {expected_side_length}, 正方形中心应为原点(0,0)")
                        logger.info(f"实际参数检查: 实际边长 {actual_side_length}, 实际中心 ({actual_center_x}, {actual_center_y}), 是否存在正方形: {has_square}")

                        # 将可能带单位的值转换为浮点数
                        try:
                            # 尝试获取数值部分（处理可能的单位）
                            actual_side_length_value = float(str(actual_side_length).split()[0]) if isinstance(actual_side_length, str) else float(actual_side_length)
                            actual_center_x_value = float(str(actual_center_x).split()[0]) if isinstance(actual_center_x, str) else float(actual_center_x)
                            actual_center_y_value = float(str(actual_center_y).split()[0]) if isinstance(actual_center_y, str) else float(actual_center_y)
                            
                            # 允许一定的误差范围（0.01）
                            side_length_error = abs(actual_side_length_value - expected_side_length) <= 0.01
                            center_x_error = abs(actual_center_x_value) <= 0.01  # 原点x坐标为0
                            center_y_error = abs(actual_center_y_value) <= 0.01  # 原点y坐标为0
                        except Exception as e:
                            logger.error(f"参数比较出错: {str(e)}")
                            side_length_error = False
                            center_x_error = False
                            center_y_error = False
                        
                        if has_square and side_length_error and center_x_error and center_y_error:
                            # 更新第二个关键步骤状态
                            updates.append({
                                'status': 'key_step',
                                'index': 2,
                                'name': '创建正方形并保存成功'
                            })
                            
                            # 任务成功完成
                            updates.append({
                                'status': 'success',
                                'reason': '成功创建了符合要求的正方形并保存'
                            })
                        else:
                            logger.warning(f"参数验证失败: 期望边长 {expected_side_length}, 正方形中心应为原点(0,0)")
                
            elif event_type == ERROR:
                error_type = payload.get("error_type", "unknown")
                error_message = payload.get("message", "未知错误")
                
                logger.error(f"钩子脚本错误 ({error_type}): {error_message}")
                
                # 记录错误事件
                updates.append({
                    'status': 'error',
                    'type': error_type,
                    'message': error_message
                })
                
    elif message.get('type') == 'error':
        logger.error(f"钩子脚本错误: {message.get('stack', '')}")
        
        # 记录错误事件
        updates.append({
            'status': 'error',
            'type': 'script_error',
            'message': message.get('stack', '未知错误')
        })
    
    return updates if updates else None
