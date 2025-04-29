#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FreeCAD带倾斜矩形凹槽的圆柱体事件处理器（通过subtractive box实现）
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
CYLINDER_RADIUS = "cylinder_radius"
CYLINDER_HEIGHT = "cylinder_height"
GROOVE_WIDTH = "groove_width"
GROOVE_DEPTH = "groove_depth"
GROOVE_HEIGHT = "groove_height"
GROOVE_ANGLE = "groove_angle"
HAS_GROOVE = "has_groove"

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
            logger.warning("未找到带倾斜矩形凹槽的圆柱体对象")
            return None
            
        # 验证结果格式
        required_keys = [
            CYLINDER_RADIUS, CYLINDER_HEIGHT,
            GROOVE_WIDTH, GROOVE_DEPTH, GROOVE_HEIGHT, GROOVE_ANGLE, HAS_GROOVE
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
                        # 检查带凹槽圆柱体参数是否符合预期
                        expected_cylinder_radius = task_parameter.get(CYLINDER_RADIUS, 20.0)
                        expected_cylinder_height = task_parameter.get(CYLINDER_HEIGHT, 40.0)
                        expected_groove_width = task_parameter.get(GROOVE_WIDTH, 10.0)
                        expected_groove_depth = task_parameter.get(GROOVE_DEPTH, 5.0)
                        expected_groove_height = task_parameter.get(GROOVE_HEIGHT, 30.0)
                        expected_groove_angle = task_parameter.get(GROOVE_ANGLE, 30.0)

                        actual_cylinder_radius = result[CYLINDER_RADIUS]
                        actual_cylinder_height = result[CYLINDER_HEIGHT]
                        actual_groove_width = result[GROOVE_WIDTH]
                        actual_groove_depth = result[GROOVE_DEPTH]
                        actual_groove_height = result[GROOVE_HEIGHT]
                        actual_groove_angle = result[GROOVE_ANGLE]
                        actual_has_groove = result[HAS_GROOVE]

                        # 日志记录关键参数
                        logger.info(f"任务参数检查: 期望圆柱体 半径={expected_cylinder_radius}, 高度={expected_cylinder_height}")
                        logger.info(f"期望矩形凹槽: 宽度={expected_groove_width}, 深度={expected_groove_depth}, " + 
                                   f"高度={expected_groove_height}, 角度={expected_groove_angle}")
                        logger.info(f"实际参数: 实际圆柱体 半径={actual_cylinder_radius}, 高度={actual_cylinder_height}")
                        logger.info(f"实际矩形凹槽: 宽度={actual_groove_width}, 深度={actual_groove_depth}, " +
                                   f"高度={actual_groove_height}, 角度={actual_groove_angle}, " +
                                   f"是否有凹槽: {actual_has_groove}")

                        try:
                            # 尝试获取数值部分（处理可能的单位）
                            actual_cylinder_radius_value = float(str(actual_cylinder_radius).split()[0]) if isinstance(actual_cylinder_radius, str) else float(actual_cylinder_radius)
                            actual_cylinder_height_value = float(str(actual_cylinder_height).split()[0]) if isinstance(actual_cylinder_height, str) else float(actual_cylinder_height)
                            
                            actual_groove_width_value = float(str(actual_groove_width).split()[0]) if isinstance(actual_groove_width, str) else float(actual_groove_width)
                            actual_groove_depth_value = float(str(actual_groove_depth).split()[0]) if isinstance(actual_groove_depth, str) else float(actual_groove_depth)
                            actual_groove_height_value = float(str(actual_groove_height).split()[0]) if isinstance(actual_groove_height, str) else float(actual_groove_height)
                            actual_groove_angle_value = float(str(actual_groove_angle).split()[0]) if isinstance(actual_groove_angle, str) else float(actual_groove_angle)
                            
                            # 允许一定的误差范围（0.01%）
                            cylinder_radius_error = abs((actual_cylinder_radius_value - expected_cylinder_radius) / expected_cylinder_radius) <= 0.0001
                            cylinder_height_error = abs((actual_cylinder_height_value - expected_cylinder_height) / expected_cylinder_height) <= 0.0001
                            
                            groove_width_error = abs((actual_groove_width_value - expected_groove_width) / expected_groove_width) <= 0.0001
                            groove_depth_error = abs((actual_groove_depth_value - expected_groove_depth) / expected_groove_depth) <= 0.0001
                            groove_height_error = abs((actual_groove_height_value - expected_groove_height) / expected_groove_height) <= 0.0001
                            # 角度允许一定误差（绝对误差1.0度）
                            groove_angle_error = abs(actual_groove_angle_value - expected_groove_angle) <= 1.0
                            
                            has_groove_correct = actual_has_groove
                        except Exception as e:
                            logger.error(f"参数比较出错: {str(e)}")
                            cylinder_radius_error = False
                            cylinder_height_error = False
                            groove_width_error = False
                            groove_depth_error = False
                            groove_height_error = False
                            groove_angle_error = False
                            has_groove_correct = False
                        
                        cylinder_correct = cylinder_radius_error and cylinder_height_error
                        groove_correct = (groove_width_error and groove_depth_error and
                                        groove_height_error and groove_angle_error and
                                        has_groove_correct)
                        
                        if cylinder_correct and groove_correct:
                            # 更新第二个关键步骤状态
                            updates.append({
                                'status': 'key_step',
                                'index': 2,
                                'name': '创建带倾斜矩形凹槽的圆柱体并保存成功'
                            })
                            
                            # 任务成功完成
                            updates.append({
                                'status': 'success',
                                'reason': '成功创建了符合要求的带倾斜矩形凹槽的圆柱体并保存'
                            })
                        else:
                            logger.warning(f"参数验证失败: " + 
                                          f"圆柱体正确: {cylinder_correct}, " +
                                          f"矩形凹槽正确: {groove_correct}")
                
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
