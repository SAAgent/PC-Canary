#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FreeCAD带楔形切口长方体事件处理器
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
WEDGE_XMIN = "wedge_Xmin"
WEDGE_XMAX = "wedge_Xmax"
WEDGE_YMIN = "wedge_Ymin"
WEDGE_YMAX = "wedge_Ymax"
WEDGE_ZMIN = "wedge_Zmin"
WEDGE_ZMAX = "wedge_Zmax"
WEDGE_X2MIN = "wedge_X2min"
WEDGE_X2MAX = "wedge_X2max"
WEDGE_Z2MIN = "wedge_Z2min"
WEDGE_Z2MAX = "wedge_Z2max"
HAS_WEDGE_CUT = "has_wedge_cut"

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
            logger.warning("未找到带楔形切口长方体对象")
            return None
            
        # 验证结果格式
        required_keys = [
            CUBE_LENGTH, CUBE_WIDTH, CUBE_HEIGHT, 
            WEDGE_XMIN, WEDGE_XMAX, WEDGE_YMIN, WEDGE_YMAX,
            WEDGE_ZMIN, WEDGE_ZMAX, WEDGE_X2MIN, WEDGE_X2MAX,
            WEDGE_Z2MIN, WEDGE_Z2MAX, HAS_WEDGE_CUT
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
                        # 检查带楔形切口长方体参数是否符合预期
                        expected_cube_length = task_parameter.get(CUBE_LENGTH, 30)
                        expected_cube_width = task_parameter.get(CUBE_WIDTH, 20)
                        expected_cube_height = task_parameter.get(CUBE_HEIGHT, 15)
                        expected_wedge_Xmin = task_parameter.get(WEDGE_XMIN, 0.0)
                        expected_wedge_Xmax = task_parameter.get(WEDGE_XMAX, 20.0)
                        expected_wedge_Ymin = task_parameter.get(WEDGE_YMIN, 0.0)
                        expected_wedge_Ymax = task_parameter.get(WEDGE_YMAX, 10.0)
                        expected_wedge_Zmin = task_parameter.get(WEDGE_ZMIN, 0.0)
                        expected_wedge_Zmax = task_parameter.get(WEDGE_ZMAX, 10.0)
                        expected_wedge_X2min = task_parameter.get(WEDGE_X2MIN, 10.0)
                        expected_wedge_X2max = task_parameter.get(WEDGE_X2MAX, 10.0)
                        expected_wedge_Z2min = task_parameter.get(WEDGE_Z2MIN, 5.0)
                        expected_wedge_Z2max = task_parameter.get(WEDGE_Z2MAX, 5.0)

                        actual_cube_length = result[CUBE_LENGTH]
                        actual_cube_width = result[CUBE_WIDTH]
                        actual_cube_height = result[CUBE_HEIGHT]
                        actual_wedge_Xmin = result[WEDGE_XMIN]
                        actual_wedge_Xmax = result[WEDGE_XMAX]
                        actual_wedge_Ymin = result[WEDGE_YMIN]
                        actual_wedge_Ymax = result[WEDGE_YMAX]
                        actual_wedge_Zmin = result[WEDGE_ZMIN]
                        actual_wedge_Zmax = result[WEDGE_ZMAX]
                        actual_wedge_X2min = result[WEDGE_X2MIN]
                        actual_wedge_X2max = result[WEDGE_X2MAX]
                        actual_wedge_Z2min = result[WEDGE_Z2MIN]
                        actual_wedge_Z2max = result[WEDGE_Z2MAX]
                        actual_has_wedge_cut = result[HAS_WEDGE_CUT]

                        # 日志记录关键参数
                        logger.info(f"任务参数检查: 期望长方体 {expected_cube_length}×{expected_cube_width}×{expected_cube_height}")
                        logger.info(f"期望楔形切口: Xmin={expected_wedge_Xmin}, Xmax={expected_wedge_Xmax}, " +
                                   f"Ymin={expected_wedge_Ymin}, Ymax={expected_wedge_Ymax}, " +
                                   f"Zmin={expected_wedge_Zmin}, Zmax={expected_wedge_Zmax}, " +
                                   f"X2min={expected_wedge_X2min}, X2max={expected_wedge_X2max}, " +
                                   f"Z2min={expected_wedge_Z2min}, Z2max={expected_wedge_Z2max}")
                        logger.info(f"实际参数: 实际长方体 {actual_cube_length}×{actual_cube_width}×{actual_cube_height}")
                        logger.info(f"实际楔形切口: Xmin={actual_wedge_Xmin}, Xmax={actual_wedge_Xmax}, " +
                                   f"Ymin={actual_wedge_Ymin}, Ymax={actual_wedge_Ymax}, " +
                                   f"Zmin={actual_wedge_Zmin}, Zmax={actual_wedge_Zmax}, " +
                                   f"X2min={actual_wedge_X2min}, X2max={actual_wedge_X2max}, " +
                                   f"Z2min={actual_wedge_Z2min}, Z2max={actual_wedge_Z2max}, " +
                                   f"是否有楔形切口: {actual_has_wedge_cut}")

                        # 将可能带单位的值转换为浮点数
                        try:
                            # 尝试获取数值部分（处理可能的单位）
                            actual_cube_length_value = float(str(actual_cube_length).split()[0]) if isinstance(actual_cube_length, str) else float(actual_cube_length)
                            actual_cube_width_value = float(str(actual_cube_width).split()[0]) if isinstance(actual_cube_width, str) else float(actual_cube_width)
                            actual_cube_height_value = float(str(actual_cube_height).split()[0]) if isinstance(actual_cube_height, str) else float(actual_cube_height)
                            
                            actual_wedge_Xmin_value = float(str(actual_wedge_Xmin).split()[0]) if isinstance(actual_wedge_Xmin, str) else float(actual_wedge_Xmin)
                            actual_wedge_Xmax_value = float(str(actual_wedge_Xmax).split()[0]) if isinstance(actual_wedge_Xmax, str) else float(actual_wedge_Xmax)
                            actual_wedge_Ymin_value = float(str(actual_wedge_Ymin).split()[0]) if isinstance(actual_wedge_Ymin, str) else float(actual_wedge_Ymin)
                            actual_wedge_Ymax_value = float(str(actual_wedge_Ymax).split()[0]) if isinstance(actual_wedge_Ymax, str) else float(actual_wedge_Ymax)
                            actual_wedge_Zmin_value = float(str(actual_wedge_Zmin).split()[0]) if isinstance(actual_wedge_Zmin, str) else float(actual_wedge_Zmin)
                            actual_wedge_Zmax_value = float(str(actual_wedge_Zmax).split()[0]) if isinstance(actual_wedge_Zmax, str) else float(actual_wedge_Zmax)
                            actual_wedge_X2min_value = float(str(actual_wedge_X2min).split()[0]) if isinstance(actual_wedge_X2min, str) else float(actual_wedge_X2min)
                            actual_wedge_X2max_value = float(str(actual_wedge_X2max).split()[0]) if isinstance(actual_wedge_X2max, str) else float(actual_wedge_X2max)
                            actual_wedge_Z2min_value = float(str(actual_wedge_Z2min).split()[0]) if isinstance(actual_wedge_Z2min, str) else float(actual_wedge_Z2min)
                            actual_wedge_Z2max_value = float(str(actual_wedge_Z2max).split()[0]) if isinstance(actual_wedge_Z2max, str) else float(actual_wedge_Z2max)
                            
                            # 允许一定的误差范围（0.01%）
                            cube_length_error = abs((actual_cube_length_value - expected_cube_length) / expected_cube_length) <= 0.0001
                            cube_width_error = abs((actual_cube_width_value - expected_cube_width) / expected_cube_width) <= 0.0001
                            cube_height_error = abs((actual_cube_height_value - expected_cube_height) / expected_cube_height) <= 0.0001
                            
                            wedge_Xmin_error = abs((actual_wedge_Xmin_value - expected_wedge_Xmin) / max(expected_wedge_Xmin, 0.0001)) <= 0.0001
                            wedge_Xmax_error = abs((actual_wedge_Xmax_value - expected_wedge_Xmax) / expected_wedge_Xmax) <= 0.0001
                            wedge_Ymin_error = abs((actual_wedge_Ymin_value - expected_wedge_Ymin) / max(expected_wedge_Ymin, 0.0001)) <= 0.0001
                            wedge_Ymax_error = abs((actual_wedge_Ymax_value - expected_wedge_Ymax) / expected_wedge_Ymax) <= 0.0001
                            wedge_Zmin_error = abs((actual_wedge_Zmin_value - expected_wedge_Zmin) / max(expected_wedge_Zmin, 0.0001)) <= 0.0001
                            wedge_Zmax_error = abs((actual_wedge_Zmax_value - expected_wedge_Zmax) / expected_wedge_Zmax) <= 0.0001
                            wedge_X2min_error = abs((actual_wedge_X2min_value - expected_wedge_X2min) / expected_wedge_X2min) <= 0.0001
                            wedge_X2max_error = abs((actual_wedge_X2max_value - expected_wedge_X2max) / expected_wedge_X2max) <= 0.0001
                            wedge_Z2min_error = abs((actual_wedge_Z2min_value - expected_wedge_Z2min) / expected_wedge_Z2min) <= 0.0001
                            wedge_Z2max_error = abs((actual_wedge_Z2max_value - expected_wedge_Z2max) / expected_wedge_Z2max) <= 0.0001
                            has_wedge_cut_correct = actual_has_wedge_cut
                        except Exception as e:
                            logger.error(f"参数比较出错: {str(e)}")
                            cube_length_error = False
                            cube_width_error = False
                            cube_height_error = False
                            wedge_Xmin_error = False
                            wedge_Xmax_error = False
                            wedge_Ymin_error = False
                            wedge_Ymax_error = False
                            wedge_Zmin_error = False
                            wedge_Zmax_error = False
                            wedge_X2min_error = False
                            wedge_X2max_error = False
                            wedge_Z2min_error = False
                            wedge_Z2max_error = False
                            has_wedge_cut_correct = False
                        
                        cube_correct = cube_length_error and cube_width_error and cube_height_error
                        wedge_correct = (wedge_Xmin_error and wedge_Xmax_error and
                                       wedge_Ymin_error and wedge_Ymax_error and
                                       wedge_Zmin_error and wedge_Zmax_error and
                                       wedge_X2min_error and wedge_X2max_error and
                                       wedge_Z2min_error and wedge_Z2max_error and
                                       has_wedge_cut_correct)
                        
                        if cube_correct and wedge_correct:
                            # 更新第二个关键步骤状态
                            updates.append({
                                'status': 'key_step',
                                'index': 2,
                                'name': '创建带楔形切口的长方体并保存成功'
                            })
                            
                            # 任务成功完成
                            updates.append({
                                'status': 'success',
                                'reason': '成功创建了符合要求的带楔形切口的长方体并保存'
                            })
                        else:
                            logger.warning(f"参数验证失败: " + 
                                          f"长方体正确: {cube_correct}, " +
                                          f"楔形切口正确: {wedge_correct}")
                
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
