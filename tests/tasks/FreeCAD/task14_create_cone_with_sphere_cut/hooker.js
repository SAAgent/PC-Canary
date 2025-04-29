// FreeCAD创建带螺旋切割圆锥体监控钩子脚本
// 用于监听FreeCAD的创建带螺旋切割圆锥体操作并检测任务完成情况
// 创建带螺旋切割圆锥体后保存文件，测试程序监听到保存后查询对应文档中是否存在符合要求的带螺旋切割圆锥体

(function() {
  // 脚本常量设置
  const FUNCTION_NAME = "_ZNK3App8Document10saveToFileEPKc"
  const ORIGIN_FUNCTION_NAME = "Document::saveToFile"
  const FUNCTION_BEHAVIOR = "保存文档"

  const SCRIPT_INITIALIZED = "script_initialized"
  const FUNCTION_NOT_FOUND = "function_not_found"
  const FUNCTION_FOUND = "function_found"
  const FUNCTION_CALLED = "function_called"
  const FUNCTION_KEY_WORD_DETECTED = "function_key_word_detected"
  const ERROR = "error"
  const HOOK_INSTALLED = "hook_installed"

  const APP_NAME = "FreeCAD"
  
  // 全局变量
  let funcFound = false;
  
  // 向评估系统发送事件
  function sendEvent(eventType, data = {}) {
      const payload = {
          event: eventType,
          ...data,
          timestamp: new Date().getTime()
      };
      send(payload);
  }
  
  // 查找Document::saveToFile函数
  function getFunction() {
      // 尝试直接通过导出符号查找
      let FuncAddr = DebugSymbol.getFunctionByName(FUNCTION_NAME);
      
      // 如果没找到，报错
      if (!FuncAddr) {
          sendEvent(ERROR, {
              error_type: FUNCTION_NOT_FOUND,
              message: `无法找到${ORIGIN_FUNCTION_NAME}函数`
          });
          return null;
      }
      
      // 报告找到函数
      funcFound = true;
      sendEvent(FUNCTION_FOUND, {
          address: FuncAddr.toString(),
          message: `找到${ORIGIN_FUNCTION_NAME}函数`
      });
      
      return FuncAddr;
  }
  
  // 初始化钩子并立即执行
  function initHook() {
      sendEvent(SCRIPT_INITIALIZED, {
          message: `${APP_NAME}${FUNCTION_BEHAVIOR}监控脚本已启动`
      });
      
      // 查找搜索函数
      const funcAddr = getFunction();
      if (!funcAddr) {
          return;
      }
      
      // 安装搜索函数钩子
      Interceptor.attach(funcAddr, {
          onEnter: function(args) {
              try {
                  sendEvent(FUNCTION_CALLED, {
                      message: `拦截到${FUNCTION_BEHAVIOR}函数调用`
                  });
                  this.filename = args[1].readCString();
              } catch (error) {
                  sendEvent(ERROR, {
                      error_type: "general_error",
                      message: `执行错误: ${error.message}`
                  });
              }
          },

          onLeave: function(retval) {
              try {
                if (retval) {
                    const pythonCode = `
import freecad
import FreeCAD
import Part
import math

# 打开指定的文件
file_path = '${this.filename}'
doc = FreeCAD.open(file_path)

# 获取活动文档
if doc is None:
    result = None
else:
    # 查找圆锥体和球体切割
    cone = None
    sphere_cut = None
    
    # 检查所有对象，寻找圆锥体和球体切割
    for obj in doc.Objects:
        # 检查是否为实体对象
        if hasattr(obj, "Shape"):
            # 检查形状类型
            if hasattr(obj.Shape, "ShapeType"):
                # 对于Part设计方法创建的对象，我们需要检查子对象
                if obj.TypeId == "PartDesign::Body":
                    # 防止重复计数同一个对象
                    processed_objects = set()
                    
                    for subobj in obj.OutList:
                        if hasattr(subobj, "Shape") and hasattr(subobj.Shape, "ShapeType"):
                            # 使用 TypeId 检查是否为增料圆锥体
                            if subobj.TypeId == 'PartDesign::AdditiveCone':
                                # 使用对象ID作为唯一标识符
                                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
                                
                                # 如果这个对象已经处理过，跳过
                                if obj_id in processed_objects:
                                    continue
                                processed_objects.add(obj_id)
                                
                                if subobj.Shape.ShapeType == "Solid":
                                    # 检查是否是圆锥体，直接读取属性
                                    cone_radius1 = subobj.Radius1.Value if hasattr(subobj, "Radius1") else 0
                                    cone_radius2 = subobj.Radius2.Value if hasattr(subobj, "Radius2") else 0
                                    cone_height = subobj.Height.Value if hasattr(subobj, "Height") else 0
                                    
                                    # 存储圆锥体信息
                                    cone = {
                                        'radius1': cone_radius1,
                                        'radius2': cone_radius2,
                                        'height': cone_height
                                    }
                            
                            # 使用 TypeId 检查是否为减料球体（球体切割）
                            elif subobj.TypeId == 'PartDesign::SubtractiveSphere':
                                # 使用对象ID作为唯一标识符
                                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
                                
                                # 如果这个对象已经处理过，跳过
                                if obj_id in processed_objects:
                                    continue
                                processed_objects.add(obj_id)
                                
                                if subobj.Shape.ShapeType == "Solid":
                                    # 直接从对象获取球体属性
                                    sphere_radius = subobj.Radius.Value if hasattr(subobj, "Radius") else 0
                                    
                                    # 获取球体的位置
                                    sphere_position_x = 0.0
                                    sphere_position_y = 0.0
                                    sphere_position_z = 0.0
                                    
                                    if hasattr(subobj, "Placement") and hasattr(subobj.Placement, "Base"):
                                        sphere_position_x = subobj.Placement.Base.x
                                        sphere_position_y = subobj.Placement.Base.y
                                        sphere_position_z = subobj.Placement.Base.z
                                    
                                    # 存储球体切割信息
                                    sphere_cut = {
                                        'radius': sphere_radius,
                                        'position_x': sphere_position_x,
                                        'position_y': sphere_position_y,
                                        'position_z': sphere_position_z
                                    }
    
    # 返回结果 - 确保返回纯数字而不是带单位的值
    # 处理可能带单位的值
    def extract_value(val):
        if val is None:
            return None
        try:
            # 如果是字符串形式的带单位数值（如 "10.0 mm"），提取数值部分
            if isinstance(val, str) and ' ' in val:
                return float(val.split()[0])
            # 如果是 FreeCAD Quantity 对象，尝试转换为浮点数
            return float(val)
        except:
            # 如果无法转换，返回原始值
            return val
    
    result = {
        'cone_radius1': extract_value(cone['radius1']) if cone else None,
        'cone_radius2': extract_value(cone['radius2']) if cone else None,
        'cone_height': extract_value(cone['height']) if cone else None,
        'sphere_radius': extract_value(sphere_cut['radius']) if sphere_cut else None,
        'sphere_position_x': extract_value(sphere_cut['position_x']) if sphere_cut else None,
        'sphere_position_y': extract_value(sphere_cut['position_y']) if sphere_cut else None,
        'sphere_position_z': extract_value(sphere_cut['position_z']) if sphere_cut else None,
        'has_sphere_cut': sphere_cut is not None
    }
                    `
                    sendEvent(FUNCTION_KEY_WORD_DETECTED, {
                        message: `检测到${FUNCTION_BEHAVIOR}操作`,
                        filename: this.filename,
                        code: pythonCode
                    });
                }
                // 检测关键字
              } catch (error) {
                  sendEvent(ERROR, {
                      error_type: "general_error",
                      message: `执行错误: ${error.message}`
                  });
              }
          }
      });
      
      sendEvent(HOOK_INSTALLED, {
          message: `钩子安装完成，等待${FUNCTION_BEHAVIOR}操作...`
      });
  }
  
  // 立即执行钩子初始化
  initHook();
})();
