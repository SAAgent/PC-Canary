#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FreeCAD带倒角立方体事件处理器
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
CUBE_LENGTH = "cube_length"
CUBE_WIDTH = "cube_width"
CUBE_HEIGHT = "cube_height"
FILLET_RADIUS = "fillet_radius"
HAS_FILLET = "has_fillet"

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
            logger.warning("未找到带倒角的立方体对象")
            return None
            
        # 验证结果格式
        required_keys = [
            CUBE_LENGTH, CUBE_WIDTH, CUBE_HEIGHT, FILLET_RADIUS, HAS_FILLET
        ]
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
                        # 检查带倒角立方体参数是否符合预期
                        expected_cube_length = task_parameter.get(CUBE_LENGTH, 30.0)
                        expected_cube_width = task_parameter.get(CUBE_WIDTH, 30.0)
                        expected_cube_height = task_parameter.get(CUBE_HEIGHT, 30.0)
                        expected_fillet_radius = task_parameter.get(FILLET_RADIUS, 5.0)

                        actual_cube_length = result[CUBE_LENGTH]
                        actual_cube_width = result[CUBE_WIDTH]
                        actual_cube_height = result[CUBE_HEIGHT]
                        actual_fillet_radius = result[FILLET_RADIUS]
                        actual_has_fillet = result[HAS_FILLET]

                        # 日志记录关键参数
                        logger.info(f"任务参数检查: 期望立方体 长={expected_cube_length}, 宽={expected_cube_width}, 高={expected_cube_height}")
                        logger.info(f"期望倒角: 半径={expected_fillet_radius}")
                        logger.info(f"实际参数: 实际立方体 长={actual_cube_length}, 宽={actual_cube_width}, 高={actual_cube_height}")
                        logger.info(f"实际倒角: 半径={actual_fillet_radius}, 是否有倒角: {actual_has_fillet}")

                        try:
                            # 尝试获取数值部分（处理可能的单位）
                            actual_cube_length_value = float(str(actual_cube_length).split()[0]) if isinstance(actual_cube_length, str) else float(actual_cube_length)
                            actual_cube_width_value = float(str(actual_cube_width).split()[0]) if isinstance(actual_cube_width, str) else float(actual_cube_width)
                            actual_cube_height_value = float(str(actual_cube_height).split()[0]) if isinstance(actual_cube_height, str) else float(actual_cube_height)
                            
                            actual_fillet_radius_value = float(str(actual_fillet_radius).split()[0]) if isinstance(actual_fillet_radius, str) else float(actual_fillet_radius)
                            
                            # 允许一定的误差范围（0.01%）
                            cube_length_error = abs((actual_cube_length_value - expected_cube_length) / expected_cube_length) <= 0.0001
                            cube_width_error = abs((actual_cube_width_value - expected_cube_width) / expected_cube_width) <= 0.0001
                            cube_height_error = abs((actual_cube_height_value - expected_cube_height) / expected_cube_height) <= 0.0001
                            
                            fillet_radius_error = abs((actual_fillet_radius_value - expected_fillet_radius) / expected_fillet_radius) <= 0.0001
                            
                            has_fillet_correct = actual_has_fillet
                        except Exception as e:
                            logger.error(f"参数比较出错: {str(e)}")
                            cube_length_error = False
                            cube_width_error = False
                            cube_height_error = False
                            fillet_radius_error = False
                            has_fillet_correct = False
                        
                        cube_correct = cube_length_error and cube_width_error and cube_height_error
                        fillet_correct = fillet_radius_error and has_fillet_correct
                        
                        if cube_correct and fillet_correct:
                            # 更新第二个关键步骤状态
                            updates.append({
                                'status': 'key_step',
                                'index': 2,
                                'name': '创建带倒角的立方体并保存成功'
                            })
                            
                            # 任务成功完成
                            updates.append({
                                'status': 'success',
                                'reason': '成功创建了符合要求的带倒角的立方体并保存'
                            })
                        else:
                            logger.warning(f"参数验证失败: " + 
                                          f"立方体正确: {cube_correct}, " +
                                          f"倒角正确: {fillet_correct}")
                
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
