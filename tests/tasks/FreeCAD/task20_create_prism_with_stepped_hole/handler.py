#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FreeCAD带阶梯孔的三棱柱事件处理器
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
PRISM_CIRCUMRADIUS = "prism_circumradius"
PRISM_HEIGHT = "prism_height"
HOLE_INNER_RADIUS = "hole_inner_radius"
HOLE_OUTER_RADIUS = "hole_outer_radius"
HOLE_DEPTH = "hole_depth"
INNER_HOLE_THROUGH = "inner_hole_through"


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
            logger.warning("未找到带阶梯孔的三棱柱对象")
            return None
            
        # 验证结果格式
        required_keys = [
            PRISM_CIRCUMRADIUS, PRISM_HEIGHT, HOLE_INNER_RADIUS, HOLE_OUTER_RADIUS, HOLE_DEPTH, INNER_HOLE_THROUGH
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
                        # 检查三棱柱参数是否符合预期
                        expected_prism_circumradius = task_parameter.get(PRISM_CIRCUMRADIUS, 35.0)
                        expected_prism_height = task_parameter.get(PRISM_HEIGHT, 40.0)
                        expected_hole_inner_radius = task_parameter.get(HOLE_INNER_RADIUS, 5.0)
                        expected_hole_outer_radius = task_parameter.get(HOLE_OUTER_RADIUS, 10.0)
                        expected_hole_depth = task_parameter.get(HOLE_DEPTH, 15.0)
                        expected_inner_hole_through = task_parameter.get(INNER_HOLE_THROUGH, True)

                        actual_prism_circumradius = result[PRISM_CIRCUMRADIUS]
                        actual_prism_height = result[PRISM_HEIGHT]
                        actual_hole_inner_radius = result[HOLE_INNER_RADIUS]
                        actual_hole_outer_radius = result[HOLE_OUTER_RADIUS]
                        actual_hole_depth = result[HOLE_DEPTH]
                        actual_inner_hole_through = result[INNER_HOLE_THROUGH]

                        # 日志记录关键参数
                        logger.info(f"任务参数检查: 期望三棱柱 外接圆半径={expected_prism_circumradius}, 高={expected_prism_height}")
                        logger.info(f"期望阶梯孔 内径={expected_hole_inner_radius}, 外径={expected_hole_outer_radius}, 深度={expected_hole_depth}")
                        logger.info(f"期望内部小孔是否贯穿: {expected_inner_hole_through}")
                        logger.info(f"实际参数: 实际三棱柱 外接圆半径={actual_prism_circumradius}, 高={actual_prism_height}")
                        logger.info(f"实际阶梯孔 内径={actual_hole_inner_radius}, 外径={actual_hole_outer_radius}, 深度={actual_hole_depth}")
                        logger.info(f"实际内部小孔是否贯穿: {actual_inner_hole_through}")

                        # 验证参数
                        # 直接比较外接圆半径和高度
                        prism_correct = (abs(actual_prism_circumradius - expected_prism_circumradius) <= 1.0 and
                                        abs(actual_prism_height - expected_prism_height) <= 1.0)
                        hole_correct = (abs(actual_hole_inner_radius - expected_hole_inner_radius) <= 0.5 and
                                        abs(actual_hole_outer_radius - expected_hole_outer_radius) <= 0.5 and
                                        abs(actual_hole_depth - expected_hole_depth) <= 1.0 and
                                        actual_inner_hole_through == expected_inner_hole_through)

                        if prism_correct and hole_correct:
                            # 更新第二个关键步骤状态
                            updates.append({
                                'status': 'key_step',
                                'index': 2,
                                'name': '创建带阶梯孔的三棱柱并保存成功'
                            })
                            
                            # 任务成功完成
                            updates.append({
                                'status': 'success',
                                'reason': '成功创建了符合要求的带阶梯孔的三棱柱并保存'
                            })
                        else:
                            logger.warning(f"参数验证失败: " + 
                                          f"三棱柱正确: {prism_correct}, " +
                                          f"阶梯孔正确: {hole_correct}")
                
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
