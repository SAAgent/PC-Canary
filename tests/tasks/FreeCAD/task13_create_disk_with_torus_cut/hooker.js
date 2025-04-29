// FreeCAD创建带环形槽圆盘监控钩子脚本
// 用于监听FreeCAD的创建带环形槽圆盘操作并检测任务完成情况
// 创建带环形槽圆盘后保存文件，测试程序监听到保存后查询对应文档中是否存在符合要求的带环形槽圆盘

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
    # 查找圆盘和环形槽
    disk = None
    torus_cut = None
    
    # 检查所有对象，寻找圆盘（圆柱体）和环形槽（环形体）
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
                            # 使用 TypeId 检查是否为增料圆柱体（圆盘）
                            if subobj.TypeId == 'PartDesign::AdditiveCylinder':
                                # 使用对象ID作为唯一标识符
                                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
                                
                                # 如果这个对象已经处理过，跳过
                                if obj_id in processed_objects:
                                    continue
                                processed_objects.add(obj_id)
                                
                                if subobj.Shape.ShapeType == "Solid" and hasattr(subobj.Shape, "Volume"):
                                    # 检查是否是圆盘，直接读取属性
                                    disk_radius = subobj.Radius.Value if hasattr(subobj, "Radius") else 0
                                    disk_height = subobj.Height.Value if hasattr(subobj, "Height") else 0
                                    
                                    # 存储圆盘信息
                                    disk = {
                                        'radius': disk_radius,
                                        'height': disk_height
                                    }
                            
                            # 使用 TypeId 检查是否为减料环形体（环形槽）
                            elif subobj.TypeId == 'PartDesign::SubtractiveTorus':
                                # 使用对象ID作为唯一标识符
                                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
                                
                                # 如果这个对象已经处理过，跳过
                                if obj_id in processed_objects:
                                    continue
                                processed_objects.add(obj_id)
                                
                                if subobj.Shape.ShapeType == "Solid" and hasattr(subobj.Shape, "Volume"):
                                    # 直接从对象获取环形体属性
                                    torus_radius1 = subobj.Radius1.Value if hasattr(subobj, "Radius1") else 0
                                    torus_radius2 = subobj.Radius2.Value if hasattr(subobj, "Radius2") else 0
                                    torus_angle1 = subobj.Angle1 if hasattr(subobj, "Angle1") else 0
                                    torus_angle2 = subobj.Angle2 if hasattr(subobj, "Angle2") else 0
                                    torus_angle3 = subobj.Angle3 if hasattr(subobj, "Angle3") else 360
                                    
                                    # 存储环形槽信息
                                    torus_cut = {
                                        'radius1': torus_radius1,
                                        'radius2': torus_radius2,
                                        'angle1': torus_angle1,
                                        'angle2': torus_angle2,
                                        'angle3': torus_angle3
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
    'disk_radius': extract_value(disk['radius']) if disk else None,
    'disk_height': extract_value(disk['height']) if disk else None,
    'torus_radius1': extract_value(torus_cut['radius1']) if torus_cut else None,
    'torus_radius2': extract_value(torus_cut['radius2']) if torus_cut else None,
    'torus_angle1': extract_value(torus_cut['angle1']) if torus_cut else None,
    'torus_angle2': extract_value(torus_cut['angle2']) if torus_cut else None,
    'torus_angle3': extract_value(torus_cut['angle3']) if torus_cut else None,
    'has_torus_cut': torus_cut is not None
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
