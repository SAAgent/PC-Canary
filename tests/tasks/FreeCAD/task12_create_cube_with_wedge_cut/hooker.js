// FreeCAD创建带楔形切口长方体监控钩子脚本
// 用于监听FreeCAD的创建带楔形切口长方体操作并检测任务完成情况
// 创建带楔形切口长方体后保存文件，测试程序监听到保存后查询对应文档中是否存在符合要求的带楔形切口长方体

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
    # 查找文档中的长方体和楔形切口
    main_cube = None
    wedge_cut = None
    
    # 检查所有对象，寻找长方体和楔形切口
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
                            # 使用 TypeId 检查是否为增料长方体
                            if subobj.TypeId == 'PartDesign::AdditiveBox' or subobj.TypeId == 'Part::Box':
                                # 使用对象ID作为唯一标识符
                                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
                                
                                # 如果这个对象已经处理过，跳过
                                if obj_id in processed_objects:
                                    continue
                                processed_objects.add(obj_id)
                                
                                if subobj.Shape.ShapeType == "Solid" and hasattr(subobj.Shape, "Volume"):
                                    # 获取长方体的尺寸
                                    cube_length = subobj.Length.Value if hasattr(subobj, "Length") else 0
                                    cube_width = subobj.Width.Value if hasattr(subobj, "Width") else 0
                                    cube_height = subobj.Height.Value if hasattr(subobj, "Height") else 0
                                    
                                    # 获取位置信息
                                    cube_position = None
                                    if hasattr(subobj, "Placement") and hasattr(subobj.Placement, "Base"):
                                        cube_position = {
                                            'x': subobj.Placement.Base.x,
                                            'y': subobj.Placement.Base.y,
                                            'z': subobj.Placement.Base.z
                                        }
                                    
                                    # 存储长方体信息
                                    main_cube = {
                                        'length': cube_length,
                                        'width': cube_width,
                                        'height': cube_height,
                                        'position': cube_position
                                    }
                            
                            # 使用 TypeId 检查是否为减料楔形
                            elif subobj.TypeId == 'PartDesign::SubtractiveWedge' or subobj.TypeId.endswith('::Wedge'):
                                # 使用对象ID作为唯一标识符
                                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
                                
                                # 如果这个对象已经处理过，跳过
                                if obj_id in processed_objects:
                                    continue
                                processed_objects.add(obj_id)
                                
                                if subobj.Shape.ShapeType == "Solid" and hasattr(subobj.Shape, "Volume"):
                                    # 获取楔形的尺寸参数
                                    wedge_Xmin = subobj.Xmin.Value if hasattr(subobj, "Xmin") else 0.0
                                    wedge_Xmax = subobj.Xmax.Value if hasattr(subobj, "Xmax") else 0.0
                                    wedge_Ymin = subobj.Ymin.Value if hasattr(subobj, "Ymin") else 0.0
                                    wedge_Ymax = subobj.Ymax.Value if hasattr(subobj, "Ymax") else 0.0
                                    wedge_Zmin = subobj.Zmin.Value if hasattr(subobj, "Zmin") else 0.0
                                    wedge_Zmax = subobj.Zmax.Value if hasattr(subobj, "Zmax") else 0.0
                                    wedge_X2min = subobj.X2min.Value if hasattr(subobj, "X2min") else 0.0
                                    wedge_X2max = subobj.X2max.Value if hasattr(subobj, "X2max") else 0.0
                                    wedge_Z2min = subobj.Z2min.Value if hasattr(subobj, "Z2min") else 0.0
                                    wedge_Z2max = subobj.Z2max.Value if hasattr(subobj, "Z2max") else 0.0
                                    
                                    # 获取位置信息
                                    wedge_position = None
                                    if hasattr(subobj, "Placement") and hasattr(subobj.Placement, "Base"):
                                        wedge_position = {
                                            'x': subobj.Placement.Base.x,
                                            'y': subobj.Placement.Base.y,
                                            'z': subobj.Placement.Base.z
                                        }
                                    
                                    # 存储楔形信息
                                    wedge_cut = {
                                        'Xmin': wedge_Xmin,
                                        'Xmax': wedge_Xmax,
                                        'Ymin': wedge_Ymin,
                                        'Ymax': wedge_Ymax,
                                        'Zmin': wedge_Zmin,
                                        'Zmax': wedge_Zmax,
                                        'X2min': wedge_X2min,
                                        'X2max': wedge_X2max,
                                        'Z2min': wedge_Z2min,
                                        'Z2max': wedge_Z2max,
                                        'position': wedge_position
                                    }
    
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
    
    # 返回结果
    result = {
        'cube_length': extract_value(main_cube['length']) if main_cube else None,
        'cube_width': extract_value(main_cube['width']) if main_cube else None,
        'cube_height': extract_value(main_cube['height']) if main_cube else None,
        'wedge_Xmin': extract_value(wedge_cut['Xmin']) if wedge_cut else None,
        'wedge_Xmax': extract_value(wedge_cut['Xmax']) if wedge_cut else None,
        'wedge_Ymin': extract_value(wedge_cut['Ymin']) if wedge_cut else None,
        'wedge_Ymax': extract_value(wedge_cut['Ymax']) if wedge_cut else None,
        'wedge_Zmin': extract_value(wedge_cut['Zmin']) if wedge_cut else None,
        'wedge_Zmax': extract_value(wedge_cut['Zmax']) if wedge_cut else None,
        'wedge_X2min': extract_value(wedge_cut['X2min']) if wedge_cut else None,
        'wedge_X2max': extract_value(wedge_cut['X2max']) if wedge_cut else None,
        'wedge_Z2min': extract_value(wedge_cut['Z2min']) if wedge_cut else None,
        'wedge_Z2max': extract_value(wedge_cut['Z2max']) if wedge_cut else None,
        'has_wedge_cut': wedge_cut is not None
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
