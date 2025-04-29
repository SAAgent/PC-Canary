#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FreeCAD带螺纹孔圆盘事件处理器
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
DISK_RADIUS = "disk_radius"
DISK_HEIGHT = "disk_height"
THREAD_SIZE = "thread_size"
THREAD_DEPTH = "thread_depth"
MODEL_THREAD = "model_thread"
HAS_THREAD = "has_thread"
IS_CENTERED = "is_centered"

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
            logger.warning("未找到带螺纹孔的圆盘对象")
            return None
            
        # 验证结果格式
        required_keys = [
            DISK_RADIUS, DISK_HEIGHT, THREAD_SIZE, THREAD_DEPTH, 
            MODEL_THREAD, HAS_THREAD, IS_CENTERED
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
                        # 检查带螺纹孔圆盘参数是否符合预期
                        expected_disk_radius = task_parameter.get(DISK_RADIUS, 50.0)
                        expected_disk_height = task_parameter.get(DISK_HEIGHT, 10.0)
                        expected_thread_size = task_parameter.get(THREAD_SIZE, "M10")
                        expected_thread_depth = task_parameter.get(THREAD_DEPTH, 10.0)
                        expected_model_thread = task_parameter.get(MODEL_THREAD, True)

                        actual_disk_radius = result[DISK_RADIUS]
                        actual_disk_height = result[DISK_HEIGHT]
                        actual_thread_size = result[THREAD_SIZE]
                        actual_thread_depth = result[THREAD_DEPTH]
                        actual_model_thread = result[MODEL_THREAD]
                        actual_has_thread = result[HAS_THREAD]
                        actual_is_centered = result[IS_CENTERED]

                        # 日志记录关键参数
                        logger.info(f"任务参数检查:")
                        logger.info(f"期望圆盘: 半径={expected_disk_radius}, 高度={expected_disk_height}")
                        logger.info(f"期望螺纹孔: Size={expected_thread_size}, 深度={expected_thread_depth}")
                        logger.info(f"期望模型螺纹: {expected_model_thread}")
                        
                        logger.info(f"实际圆盘: 半径={actual_disk_radius}, 高度={actual_disk_height}")
                        logger.info(f"实际螺纹孔: Size={actual_thread_size}, 深度={actual_thread_depth}")
                        logger.info(f"实际模型螺纹: {actual_model_thread}")
                        logger.info(f"是否有螺纹: {actual_has_thread}, 是否居中: {actual_is_centered}")

                        try:
                            # 尝试获取数值部分（处理可能的单位）
                            def get_float_value(value):
                                if isinstance(value, str) and ' ' in value:
                                    return float(value.split()[0])
                                return float(value)
                            
                            actual_disk_radius_value = get_float_value(actual_disk_radius)
                            actual_disk_height_value = get_float_value(actual_disk_height)
                            actual_thread_depth_value = get_float_value(actual_thread_depth)
                            
                            # 允许一定的误差范围（0.01%）
                            disk_radius_error = abs((actual_disk_radius_value - expected_disk_radius) / expected_disk_radius) <= 0.0001
                            disk_height_error = abs((actual_disk_height_value - expected_disk_height) / expected_disk_height) <= 0.0001
                            thread_depth_error = abs((actual_thread_depth_value - expected_thread_depth) / expected_thread_depth) <= 0.0001
                            
                            # 检查螺纹参数是否匹配
                            def compare_str(actual, expected):
                                return actual.strip().lower() == expected.strip().lower()
                                
                            thread_size_correct = compare_str(actual_thread_size, expected_thread_size)
                            model_thread_correct = actual_model_thread == expected_model_thread
                            
                            is_centered_correct = actual_is_centered
                            has_thread_correct = actual_has_thread
                        except Exception as e:
                            logger.error(f"参数比较出错: {str(e)}")
                            disk_radius_error = False
                            disk_height_error = False
                            thread_size_correct = False
                            thread_depth_error = False
                            model_thread_correct = False
                            is_centered_correct = False
                            has_thread_correct = False
                        
                        disk_correct = disk_radius_error and disk_height_error
                        thread_correct = (thread_size_correct and thread_depth_error and 
                                         model_thread_correct and has_thread_correct)
                        hole_correct = is_centered_correct
                        
                        if disk_correct and hole_correct and thread_correct:
                            # 更新第二个关键步骤状态
                            updates.append({
                                'status': 'key_step',
                                'index': 2,
                                'name': '创建带螺纹孔的圆盘并保存成功'
                            })
                            
                            # 任务成功完成
                            updates.append({
                                'status': 'success',
                                'reason': '成功创建了符合要求的带螺纹孔的圆盘并保存'
                            })
                        else:
                            logger.warning(f"参数验证失败: " + 
                                          f"圆盘正确: {disk_correct}, " +
                                          f"孔位置正确: {hole_correct}, " +
                                          f"螺纹正确: {thread_correct}")
                
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
