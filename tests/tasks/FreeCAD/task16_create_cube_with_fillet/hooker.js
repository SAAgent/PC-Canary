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
    processed_objects = set()  # To track processed objects
    # Check all objects, looking for cube and fillets
    for subobj in doc.Objects:
        if hasattr(subobj, "Shape") and hasattr(subobj.Shape, "ShapeType"):
            # Use TypeId to check if it's an additive cube
            if subobj.TypeId == 'PartDesign::AdditiveBox' or subobj.TypeId == 'Part::Box':
                # Use object ID as a unique identifier
                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
                
                # If this object has already been processed, skip it
                if obj_id in processed_objects:
                    continue
                processed_objects.add(obj_id)
                
                if subobj.Shape.ShapeType == "Solid":
                    # Check if it's a cube, read properties directly
                    cube_length = subobj.Length.Value if hasattr(subobj, "Length") else 0
                    cube_width = subobj.Width.Value if hasattr(subobj, "Width") else 0
                    cube_height = subobj.Height.Value if hasattr(subobj, "Height") else 0
                    
                    # Store cube information
                    cube = {
                        'length': cube_length,
                        'width': cube_width,
                        'height': cube_height
                    }
            
            # Check if there are fillet features (could be multiple types)
            elif subobj.TypeId == 'PartDesign::Fillet' or 'Fillet' in subobj.TypeId:
                # Use object ID as a unique identifier
                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
                
                # If this object has already been processed, skip it
                if obj_id in processed_objects:
                    continue
                processed_objects.add(obj_id)
                
                # Mark that fillets exist
                has_fillet = True
                
                # Try to get the fillet radius
                if hasattr(subobj, "Radius"):
                    if isinstance(subobj.Radius, list):
                        # If it's a list, take the first value
                        if len(subobj.Radius) > 0:
                            fillet_radius = float(subobj.Radius[0])
                    else:
                        # Get value directly
                        fillet_radius = float(subobj.Radius)
                elif hasattr(subobj, "FilletRadius"):
                    fillet_radius = float(subobj.FilletRadius)
    
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
