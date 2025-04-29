// FreeCAD创建带倾斜矩形凹槽圆柱体监控钩子脚本
// 用于监听FreeCAD的创建带倾斜矩形凹槽圆柱体操作并检测任务完成情况
// 创建带倾斜矩形凹槽圆柱体后保存文件，测试程序监听到保存后查询对应文档中是否存在符合要求的带倾斜矩形凹槽圆柱体

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
    # 查找圆柱体和矩形凹槽
    cylinder = None
    groove = None
    
    # 检查所有对象，寻找圆柱体和矩形凹槽
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
                            # 使用 TypeId 检查是否为增料圆柱体
                            if subobj.TypeId == 'PartDesign::AdditiveCylinder':
                                # 使用对象ID作为唯一标识符
                                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
                                
                                # 如果这个对象已经处理过，跳过
                                if obj_id in processed_objects:
                                    continue
                                processed_objects.add(obj_id)
                                
                                if subobj.Shape.ShapeType == "Solid":
                                    # 检查是否是圆柱体，直接读取属性
                                    cylinder_radius = subobj.Radius.Value if hasattr(subobj, "Radius") else 0
                                    cylinder_height = subobj.Height.Value if hasattr(subobj, "Height") else 0
                                    
                                    # 存储圆柱体信息
                                    cylinder = {
                                        'radius': cylinder_radius,
                                        'height': cylinder_height
                                    }
                            
                            # 使用 TypeId 检查是否为减料盒体（矩形凹槽）
                            elif subobj.TypeId == 'PartDesign::SubtractiveBox':
                                # 使用对象ID作为唯一标识符
                                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
                                
                                # 如果这个对象已经处理过，跳过
                                if obj_id in processed_objects:
                                    continue
                                processed_objects.add(obj_id)
                                
                                if subobj.Shape.ShapeType == "Solid":
                                    # 获取矩形凹槽的基本属性
                                    # 矩形凹槽的高度、宽度和深度
                                    groove_width = 0
                                    groove_height = 0
                                    groove_depth = 0
                                    groove_angle = 0
                                    
                                    # 尝试从属性中提取
                                    if hasattr(subobj, "Length"):
                                        groove_width = subobj.Length.Value
                                    if hasattr(subobj, "Height"):
                                        groove_height = subobj.Height.Value
                                    if hasattr(subobj, "Width"):
                                        groove_depth = subobj.Width.Value
                                    if hasattr(subobj, "Angle"):
                                        groove_angle = subobj.Angle
                                    
                                    # 对于box，直接从边界盒获取尺寸（如果前面没有获得的话）
                                    if hasattr(subobj, "Shape") and hasattr(subobj.Shape, "BoundBox"):
                                        bounds = subobj.Shape.BoundBox
                                        if groove_width == 0:
                                            groove_width = bounds.XLength
                                        if groove_height == 0:
                                            groove_height = bounds.ZLength
                                        if groove_depth == 0:
                                            groove_depth = bounds.YLength
                                    
                                    # 通过放置位置和角度计算倾斜角度（如果尚未从属性获取）
                                    if groove_angle == 0 and hasattr(subobj, "Placement"):
                                        # 从旋转矩阵中提取角度
                                        if hasattr(subobj.Placement, "Rotation"):
                                            # 获取旋转角度（以度为单位）
                                            # 在FreeCAD中，旋转通常以弧度表示
                                            rot_angle = subobj.Placement.Rotation.Angle * 180.0 / math.pi
                                            
                                            # 提取绕y轴的旋转（通常是倾斜角度）
                                            axis = subobj.Placement.Rotation.Axis
                                            if abs(axis.y) > 0.7:  # 如果主要是绕Y轴旋转
                                                groove_angle = rot_angle
                                            else:
                                                # 计算与Y轴的夹角
                                                import math
                                                groove_angle = math.degrees(math.acos(axis.y))
                                                
                                    # 倾斜角度可能也从位置相对于圆柱体的偏移来确定
                                    # 但我们已经尝试通过旋转来获取
                                    
                                    # 存储矩形凹槽信息
                                    groove = {
                                        'width': groove_width,
                                        'depth': groove_depth,
                                        'height': groove_height,
                                        'angle': groove_angle
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
        'cylinder_radius': extract_value(cylinder['radius']) if cylinder else None,
        'cylinder_height': extract_value(cylinder['height']) if cylinder else None,
        'groove_width': extract_value(groove['width']) if groove else None,
        'groove_depth': extract_value(groove['depth']) if groove else None,
        'groove_height': extract_value(groove['height']) if groove else None,
        'groove_angle': extract_value(groove['angle']) if groove else None,
        'has_groove': groove is not None
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
