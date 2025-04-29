#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FreeCAD带半球状凹坑的圆锥体事件处理器
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
CONE_RADIUS1 = "cone_radius1"
CONE_RADIUS2 = "cone_radius2"
CONE_HEIGHT = "cone_height"
SPHERE_RADIUS = "sphere_radius"
SPHERE_POSITION_X = "sphere_position_x"
SPHERE_POSITION_Y = "sphere_position_y"
SPHERE_POSITION_Z = "sphere_position_z"
HAS_SPHERE_CUT = "has_sphere_cut"

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
            logger.warning("未找到带半球状凹坑的圆锥体对象")
            return None
            
        # 验证结果格式
        required_keys = [
            CONE_RADIUS1, CONE_RADIUS2, CONE_HEIGHT, 
            SPHERE_RADIUS, SPHERE_POSITION_X, SPHERE_POSITION_Y, 
            SPHERE_POSITION_Z, HAS_SPHERE_CUT
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
                        # 检查带球形切口圆锥体参数是否符合预期
                        expected_cone_radius1 = task_parameter.get(CONE_RADIUS1, 25.0)
                        expected_cone_radius2 = task_parameter.get(CONE_RADIUS2, 10.0)
                        expected_cone_height = task_parameter.get(CONE_HEIGHT, 40.0)
                        expected_sphere_radius = task_parameter.get(SPHERE_RADIUS, 15.0)
                        expected_sphere_position_x = task_parameter.get(SPHERE_POSITION_X, 0.0)
                        expected_sphere_position_y = task_parameter.get(SPHERE_POSITION_Y, 0.0)
                        expected_sphere_position_z = task_parameter.get(SPHERE_POSITION_Z, 25.0)

                        actual_cone_radius1 = result[CONE_RADIUS1]
                        actual_cone_radius2 = result[CONE_RADIUS2]
                        actual_cone_height = result[CONE_HEIGHT]
                        actual_sphere_radius = result[SPHERE_RADIUS]
                        actual_sphere_position_x = result[SPHERE_POSITION_X]
                        actual_sphere_position_y = result[SPHERE_POSITION_Y]
                        actual_sphere_position_z = result[SPHERE_POSITION_Z]
                        actual_has_sphere_cut = result[HAS_SPHERE_CUT]

                        # 日志记录关键参数
                        logger.info(f"任务参数检查: 期望圆锥体 底部半径={expected_cone_radius1}, 顶部半径={expected_cone_radius2}, 高度={expected_cone_height}")
                        logger.info(f"期望球形切口: 半径={expected_sphere_radius}, 位置=({expected_sphere_position_x}, {expected_sphere_position_y}, {expected_sphere_position_z})")
                        logger.info(f"实际参数: 实际圆锥体 底部半径={actual_cone_radius1}, 顶部半径={actual_cone_radius2}, 高度={actual_cone_height}")
                        logger.info(f"实际球形切口: 半径={actual_sphere_radius}, 位置=({actual_sphere_position_x}, {actual_sphere_position_y}, {actual_sphere_position_z}), " +
                                   f"是否有球形切口: {actual_has_sphere_cut}")

                        try:
                            # 尝试获取数值部分（处理可能的单位）
                            actual_cone_radius1_value = float(str(actual_cone_radius1).split()[0]) if isinstance(actual_cone_radius1, str) else float(actual_cone_radius1)
                            actual_cone_radius2_value = float(str(actual_cone_radius2).split()[0]) if isinstance(actual_cone_radius2, str) else float(actual_cone_radius2)
                            actual_cone_height_value = float(str(actual_cone_height).split()[0]) if isinstance(actual_cone_height, str) else float(actual_cone_height)
                            
                            actual_sphere_radius_value = float(str(actual_sphere_radius).split()[0]) if isinstance(actual_sphere_radius, str) else float(actual_sphere_radius)
                            actual_sphere_position_x_value = float(str(actual_sphere_position_x).split()[0]) if isinstance(actual_sphere_position_x, str) else float(actual_sphere_position_x)
                            actual_sphere_position_y_value = float(str(actual_sphere_position_y).split()[0]) if isinstance(actual_sphere_position_y, str) else float(actual_sphere_position_y)
                            actual_sphere_position_z_value = float(str(actual_sphere_position_z).split()[0]) if isinstance(actual_sphere_position_z, str) else float(actual_sphere_position_z)
                            
                            # 允许一定的误差范围（0.01%）
                            cone_radius1_error = abs((actual_cone_radius1_value - expected_cone_radius1) / expected_cone_radius1) <= 0.0001
                            cone_radius2_error = abs((actual_cone_radius2_value - expected_cone_radius2) / expected_cone_radius2) <= 0.0001
                            cone_height_error = abs((actual_cone_height_value - expected_cone_height) / expected_cone_height) <= 0.0001
                            
                            sphere_radius_error = abs((actual_sphere_radius_value - expected_sphere_radius) / expected_sphere_radius) <= 0.0001
                            # 位置坐标允许一定误差（绝对误差1.0mm）
                            sphere_position_x_error = abs(actual_sphere_position_x_value - expected_sphere_position_x) <= 1.0
                            sphere_position_y_error = abs(actual_sphere_position_y_value - expected_sphere_position_y) <= 1.0
                            sphere_position_z_error = abs(actual_sphere_position_z_value - expected_sphere_position_z) <= 1.0
                            
                            has_sphere_cut_correct = actual_has_sphere_cut
                        except Exception as e:
                            logger.error(f"参数比较出错: {str(e)}")
                            cone_radius1_error = False
                            cone_radius2_error = False
                            cone_height_error = False
                            sphere_radius_error = False
                            sphere_position_x_error = False
                            sphere_position_y_error = False
                            sphere_position_z_error = False
                            has_sphere_cut_correct = False
                        
                        cone_correct = cone_radius1_error and cone_radius2_error and cone_height_error
                        sphere_correct = (sphere_radius_error and 
                                         sphere_position_x_error and 
                                         sphere_position_y_error and
                                         sphere_position_z_error and
                                         has_sphere_cut_correct)
                        
                        if cone_correct and sphere_correct:
                            # 更新第二个关键步骤状态
                            updates.append({
                                'status': 'key_step',
                                'index': 2,
                                'name': '创建带半球状凹坑的圆锥体并保存成功'
                            })
                            
                            # 任务成功完成
                            updates.append({
                                'status': 'success',
                                'reason': '成功创建了符合要求的带半球状凹坑的圆锥体并保存'
                            })
                        else:
                            logger.warning(f"参数验证失败: " + 
                                          f"圆锥体正确: {cone_correct}, " +
                                          f"球体切割正确: {sphere_correct}")
                
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
