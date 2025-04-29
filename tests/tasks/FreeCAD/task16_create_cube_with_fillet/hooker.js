// FreeCAD创建带倒角立方体监控钩子脚本
// 用于监听FreeCAD的创建带倒角立方体操作并检测任务完成情况
// 创建带倒角立方体后保存文件，测试程序监听到保存后查询对应文档中是否存在符合要求的带倒角立方体

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
    # 查找立方体和倒角
    cube = None
    fillet = None
    has_fillet = False
    fillet_radius = 0.0
    
    # 检查所有对象，寻找立方体和倒角
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
                            # 使用 TypeId 检查是否为增料立方体
                            if subobj.TypeId == 'PartDesign::AdditiveBox' or subobj.TypeId == 'Part::Box':
                                # 使用对象ID作为唯一标识符
                                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
                                
                                # 如果这个对象已经处理过，跳过
                                if obj_id in processed_objects:
                                    continue
                                processed_objects.add(obj_id)
                                
                                if subobj.Shape.ShapeType == "Solid":
                                    # 检查是否是立方体，直接读取属性
                                    cube_length = subobj.Length.Value if hasattr(subobj, "Length") else 0
                                    cube_width = subobj.Width.Value if hasattr(subobj, "Width") else 0
                                    cube_height = subobj.Height.Value if hasattr(subobj, "Height") else 0
                                    
                                    # 存储立方体信息
                                    cube = {
                                        'length': cube_length,
                                        'width': cube_width,
                                        'height': cube_height
                                    }
                            
                            # 检查是否有倒角特征（可能是多种类型）
                            elif subobj.TypeId == 'PartDesign::Fillet' or 'Fillet' in subobj.TypeId:
                                # 使用对象ID作为唯一标识符
                                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
                                
                                # 如果这个对象已经处理过，跳过
                                if obj_id in processed_objects:
                                    continue
                                processed_objects.add(obj_id)
                                
                                # 标记存在倒角
                                has_fillet = True
                                
                                # 尝试获取倒角半径
                                if hasattr(subobj, "Radius"):
                                    if isinstance(subobj.Radius, list):
                                        # 如果是一个列表，取第一个值
                                        if len(subobj.Radius) > 0:
                                            fillet_radius = float(subobj.Radius[0])
                                    else:
                                        # 直接获取值
                                        fillet_radius = float(subobj.Radius)
                                elif hasattr(subobj, "FilletRadius"):
                                    fillet_radius = float(subobj.FilletRadius)
                                
                # 也可能是直接使用Part模块创建的对象
                elif obj.TypeId == 'Part::Box':
                    if hasattr(obj, "Length") and hasattr(obj, "Width") and hasattr(obj, "Height"):
                        # 存储立方体信息
                        cube = {
                            'length': obj.Length.Value,
                            'width': obj.Width.Value,
                            'height': obj.Height.Value
                        }
    
    # 如果在对象中没有找到倒角特征，尝试通过形状几何检测
    if not has_fillet and cube is not None:
        # 检查文档中是否有带倒角的形状特征
        for obj in doc.Objects:
            if hasattr(obj, "Shape"):
                # 检查边缘的曲率半径
                if hasattr(obj.Shape, "Edges"):
                    for edge in obj.Shape.Edges:
                        if hasattr(edge, "Curve") and hasattr(edge.Curve, "Radius"):
                            # 如果边有曲率，可能是倒角
                            edge_radius = edge.Curve.Radius
                            if edge_radius > 0 and edge_radius < min(cube['length'], cube['width'], cube['height']) / 2:
                                has_fillet = True
                                # 如果没有找到倒角特征但找到了倒角边，使用边的半径
                                if fillet_radius == 0.0:
                                    fillet_radius = edge_radius
    
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
        'cube_length': extract_value(cube['length']) if cube else None,
        'cube_width': extract_value(cube['width']) if cube else None,
        'cube_height': extract_value(cube['height']) if cube else None,
        'fillet_radius': extract_value(fillet_radius),
        'has_fillet': has_fillet
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
