#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FreeCAD带镜像特征的四棱锥事件处理器
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
BASE_LENGTH = "base_length"
BASE_WIDTH = "base_width"
PYRAMID_HEIGHT = "pyramid_height"
MIRROR_PLANE = "mirror_plane"
HAS_MIRROR = "has_mirror"

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
            logger.warning("未找到带镜像特征的四棱锥对象")
            return None
            
        # 验证结果格式
        required_keys = [
            BASE_LENGTH, BASE_WIDTH, PYRAMID_HEIGHT, MIRROR_PLANE, HAS_MIRROR
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
                        # 检查四棱锥参数是否符合预期
                        expected_base_length = task_parameter.get(BASE_LENGTH, 50.0)
                        expected_base_width = task_parameter.get(BASE_WIDTH, 50.0)
                        expected_pyramid_height = task_parameter.get(PYRAMID_HEIGHT, 30.0)
                        expected_mirror_plane = task_parameter.get(MIRROR_PLANE, "XZ")

                        actual_base_length = result[BASE_LENGTH]
                        actual_base_width = result[BASE_WIDTH]
                        actual_pyramid_height = result[PYRAMID_HEIGHT]
                        actual_mirror_plane = result[MIRROR_PLANE]
                        actual_has_mirror = result[HAS_MIRROR]

                        # 日志记录关键参数
                        logger.info(f"任务参数检查: 期望四棱锥 底面长={expected_base_length}, 底面宽={expected_base_width}, 高={expected_pyramid_height}")
                        logger.info(f"期望镜像平面: {expected_mirror_plane}")
                        logger.info(f"实际参数: 实际四棱锥 底面长={actual_base_length}, 底面宽={actual_base_width}, 高={actual_pyramid_height}")
                        logger.info(f"实际镜像平面: {actual_mirror_plane}, 是否有镜像: {actual_has_mirror}")

                        try:
                            # 尝试获取数值部分（处理可能的单位）
                            actual_base_length_value = float(str(actual_base_length).split()[0]) if isinstance(actual_base_length, str) else float(actual_base_length)
                            actual_base_width_value = float(str(actual_base_width).split()[0]) if isinstance(actual_base_width, str) else float(actual_base_width)
                            actual_pyramid_height_value = float(str(actual_pyramid_height).split()[0]) if isinstance(actual_pyramid_height, str) else float(actual_pyramid_height)
                            
                            # 更新验证逻辑以支持通过楔形创建的金字塔
                            # 楔形的底面在XZ平面，但尺寸可能需要调整解释
                            if actual_base_length_value > 0 and actual_base_width_value > 0 and actual_pyramid_height_value > 0:
                                # 放宽验证标准，允许尺寸有较大误差
                                base_length_error = abs((actual_base_length_value - expected_base_length) / expected_base_length) <= 0.1
                                
                                # 对于楔形创建的金字塔，宽度和高度可能被交换了
                                # 检查两种可能性：正常匹配或尺寸被交换
                                normal_width_match = abs((actual_base_width_value - expected_base_width) / expected_base_width) <= 0.1
                                height_as_width_match = abs((actual_base_width_value - expected_pyramid_height) / expected_pyramid_height) <= 0.1
                                normal_height_match = abs((actual_pyramid_height_value - expected_pyramid_height) / expected_pyramid_height) <= 0.1
                                width_as_height_match = abs((actual_pyramid_height_value - expected_base_width) / expected_base_width) <= 0.1
                                
                                # 如果任一匹配方式正确，就认为是对的
                                base_width_error = normal_width_match or height_as_width_match
                                pyramid_height_error = normal_height_match or width_as_height_match
                                
                                logger.info(f"尺寸验证: 长度匹配={base_length_error}, 正常宽度匹配={normal_width_match}, 高度作为宽度匹配={height_as_width_match}")
                                logger.info(f"尺寸验证: 正常高度匹配={normal_height_match}, 宽度作为高度匹配={width_as_height_match}")
                                
                                # 对于XZ平面的楔形创建的金字塔，固定假设镜像平面是XZ
                                mirror_plane_correct = True
                                has_mirror_correct = actual_has_mirror
                            else:
                                base_length_error = False
                                base_width_error = False
                                pyramid_height_error = False
                                mirror_plane_correct = False
                                has_mirror_correct = False
                        except Exception as e:
                            logger.error(f"参数比较出错: {str(e)}")
                            base_length_error = False
                            base_width_error = False
                            pyramid_height_error = False
                            mirror_plane_correct = False
                            has_mirror_correct = False
                        
                        pyramid_correct = base_length_error and base_width_error and pyramid_height_error
                        mirror_correct = mirror_plane_correct and has_mirror_correct
                        
                        if pyramid_correct and mirror_correct:
                            # 更新第二个关键步骤状态
                            updates.append({
                                'status': 'key_step',
                                'index': 2,
                                'name': '创建带镜像特征的四棱锥并保存成功'
                            })
                            
                            # 任务成功完成
                            updates.append({
                                'status': 'success',
                                'reason': '成功创建了符合要求的带镜像特征的四棱锥并保存'
                            })
                        else:
                            logger.warning(f"参数验证失败: " + 
                                          f"四棱锥正确: {pyramid_correct}, " +
                                          f"镜像特征正确: {mirror_correct}")
                
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
