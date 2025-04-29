#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FreeCAD带环形槽圆盘事件处理器
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
TORUS_RADIUS1 = "torus_radius1"
TORUS_RADIUS2 = "torus_radius2"
TORUS_ANGLE1 = "torus_angle1"
TORUS_ANGLE2 = "torus_angle2"
TORUS_ANGLE3 = "torus_angle3"
HAS_TORUS_CUT = "has_torus_cut"

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
            logger.warning("未找到带环形槽圆盘对象")
            return None
            
        # 验证结果格式
        required_keys = [
            DISK_RADIUS, DISK_HEIGHT, 
            TORUS_RADIUS1, TORUS_RADIUS2, 
            TORUS_ANGLE1, TORUS_ANGLE2, 
            TORUS_ANGLE3, HAS_TORUS_CUT
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
                        # 检查带环形槽圆盘参数是否符合预期
                        expected_disk_radius = task_parameter.get(DISK_RADIUS, 30.0)
                        expected_disk_height = task_parameter.get(DISK_HEIGHT, 10.0)
                        expected_torus_radius1 = task_parameter.get(TORUS_RADIUS1, 20.0)
                        expected_torus_radius2 = task_parameter.get(TORUS_RADIUS2, 5.0)
                        expected_torus_angle1 = task_parameter.get(TORUS_ANGLE1, 0.0)
                        expected_torus_angle2 = task_parameter.get(TORUS_ANGLE2, 0.0)
                        expected_torus_angle3 = task_parameter.get(TORUS_ANGLE3, 360.0)

                        actual_disk_radius = result[DISK_RADIUS]
                        actual_disk_height = result[DISK_HEIGHT]
                        actual_torus_radius1 = result[TORUS_RADIUS1]
                        actual_torus_radius2 = result[TORUS_RADIUS2]
                        actual_torus_angle1 = result[TORUS_ANGLE1]
                        actual_torus_angle2 = result[TORUS_ANGLE2]
                        actual_torus_angle3 = result[TORUS_ANGLE3]
                        actual_has_torus_cut = result[HAS_TORUS_CUT]

                        # 日志记录关键参数
                        logger.info(f"任务参数检查: 期望圆盘 半径={expected_disk_radius}, 高度={expected_disk_height}")
                        logger.info(f"期望环形槽: Radius1={expected_torus_radius1}, Radius2={expected_torus_radius2}, " +
                                   f"Angle1={expected_torus_angle1}, Angle2={expected_torus_angle2}, " +
                                   f"Angle3={expected_torus_angle3}")
                        logger.info(f"实际参数: 实际圆盘 半径={actual_disk_radius}, 高度={actual_disk_height}")
                        logger.info(f"实际环形槽: Radius1={actual_torus_radius1}, Radius2={actual_torus_radius2}, " +
                                   f"Angle1={actual_torus_angle1}, Angle2={actual_torus_angle2}, " +
                                   f"Angle3={actual_torus_angle3}, " +
                                   f"是否有环形槽: {actual_has_torus_cut}")

                        # 将可能带单位的值转换为浮点数
                        try:
                            # 尝试获取数值部分（处理可能的单位）
                            actual_disk_radius_value = float(str(actual_disk_radius).split()[0]) if isinstance(actual_disk_radius, str) else float(actual_disk_radius)
                            actual_disk_height_value = float(str(actual_disk_height).split()[0]) if isinstance(actual_disk_height, str) else float(actual_disk_height)
                            
                            actual_torus_radius1_value = float(str(actual_torus_radius1).split()[0]) if isinstance(actual_torus_radius1, str) else float(actual_torus_radius1)
                            actual_torus_radius2_value = float(str(actual_torus_radius2).split()[0]) if isinstance(actual_torus_radius2, str) else float(actual_torus_radius2)
                            actual_torus_angle1_value = float(str(actual_torus_angle1).split()[0]) if isinstance(actual_torus_angle1, str) else float(actual_torus_angle1)
                            actual_torus_angle2_value = float(str(actual_torus_angle2).split()[0]) if isinstance(actual_torus_angle2, str) else float(actual_torus_angle2)
                            actual_torus_angle3_value = float(str(actual_torus_angle3).split()[0]) if isinstance(actual_torus_angle3, str) else float(actual_torus_angle3)
                            
                            # 允许一定的误差范围（0.01%）
                            disk_radius_error = abs((actual_disk_radius_value - expected_disk_radius) / expected_disk_radius) <= 0.0001
                            disk_height_error = abs((actual_disk_height_value - expected_disk_height) / expected_disk_height) <= 0.0001
                            
                            torus_radius1_error = abs((actual_torus_radius1_value - expected_torus_radius1) / expected_torus_radius1) <= 0.0001
                            torus_radius2_error = abs((actual_torus_radius2_value - expected_torus_radius2) / expected_torus_radius2) <= 0.0001
                            
                            # 角度可能有多种表示方式，允许更大的误差
                            torus_angle1_error = abs(actual_torus_angle1_value - expected_torus_angle1) <= 1.0
                            torus_angle2_error = abs(actual_torus_angle2_value - expected_torus_angle2) <= 1.0
                            torus_angle3_error = abs(actual_torus_angle3_value - expected_torus_angle3) <= 1.0
                            
                            has_torus_cut_correct = actual_has_torus_cut
                        except Exception as e:
                            logger.error(f"参数比较出错: {str(e)}")
                            disk_radius_error = False
                            disk_height_error = False
                            torus_radius1_error = False
                            torus_radius2_error = False
                            torus_angle1_error = False
                            torus_angle2_error = False
                            torus_angle3_error = False
                            has_torus_cut_correct = False
                        
                        disk_correct = disk_radius_error and disk_height_error
                        torus_correct = (torus_radius1_error and torus_radius2_error and
                                        torus_angle1_error and torus_angle2_error and
                                        torus_angle3_error and has_torus_cut_correct)
                        
                        if disk_correct and torus_correct:
                            # 更新第二个关键步骤状态
                            updates.append({
                                'status': 'key_step',
                                'index': 2,
                                'name': '创建带环形槽的圆盘并保存成功'
                            })
                            
                            # 任务成功完成
                            updates.append({
                                'status': 'success',
                                'reason': '成功创建了符合要求的带环形槽的圆盘并保存'
                            })
                        else:
                            logger.warning(f"参数验证失败: " + 
                                          f"圆盘正确: {disk_correct}, " +
                                          f"环形槽正确: {torus_correct}")
                
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
