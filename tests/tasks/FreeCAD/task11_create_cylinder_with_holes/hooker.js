// FreeCAD创建带孔圆柱体监控钩子脚本
// 用于监听FreeCAD的创建带孔圆柱体操作并检测任务完成情况
// 创建带孔圆柱体后保存文件，测试程序监听到保存后查询对应文档中是否存在符合要求的带孔圆柱体

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
else:                    # 查找文档中的圆柱体和孔
    main_cylinder = None
    holes = []
    
    # 检查所有对象，寻找圆柱体和孔
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
                                
                                if subobj.Shape.ShapeType == "Solid" and hasattr(subobj.Shape, "Volume"):
                                    # 检查是否是圆柱体，直接读取属性
                                    cylinder_radius = subobj.Radius.Value if hasattr(subobj, "Radius") else 0
                                    cylinder_height = subobj.Height.Value if hasattr(subobj, "Height") else 0
                                    
                                    # 获取位置信息
                                    cylinder_position = None
                                    if hasattr(subobj, "Placement") and hasattr(subobj.Placement, "Base"):
                                        cylinder_position = {
                                            'x': subobj.Placement.Base.x,
                                            'y': subobj.Placement.Base.y,
                                            'z': subobj.Placement.Base.z
                                        }
                                    
                                    # 如果没有直接的属性，尝试从形状计算
                                    if cylinder_radius == 0 or cylinder_height == 0:
                                        if len(subobj.Shape.Faces) == 3:  # 圆柱体通常有三个面（两个底面和一个侧面）
                                            # 检查是否有圆形面
                                            circular_faces = []
                                            cylindrical_face = None
                                            
                                            for face in subobj.Shape.Faces:
                                                if face.Surface.TypeId == 'Part::GeomCylinder':
                                                    cylindrical_face = face
                                                elif face.Surface.TypeId == 'Part::GeomPlane':
                                                    # 检查边缘是否为圆形
                                                    if len(face.Edges) == 1 and face.Edges[0].Curve.TypeId == 'Part::GeomCircle':
                                                        circular_faces.append(face)
                                            
                                            # 如果找到了一个圆柱面和两个圆面，可以计算半径和高度
                                            if cylindrical_face and len(circular_faces) == 2:
                                                if cylinder_radius == 0:
                                                    cylinder_radius = circular_faces[0].Edges[0].Curve.Radius.Value if hasattr(circular_faces[0].Edges[0].Curve.Radius, "Value") else circular_faces[0].Edges[0].Curve.Radius
                                                
                                                if cylinder_height == 0:
                                                    center1 = circular_faces[0].Surface.Position
                                                    center2 = circular_faces[1].Surface.Position
                                                    cylinder_height = math.sqrt(
                                                        (center1.x - center2.x)**2 + 
                                                        (center1.y - center2.y)**2 + 
                                                        (center1.z - center2.z)**2
                                                    )
                                    
                                    # 存储圆柱体信息
                                    main_cylinder = {
                                        'radius': cylinder_radius,
                                        'height': cylinder_height,
                                        'position': cylinder_position
                                    }
                            
                            # 使用 TypeId 检查是否为减料圆柱体（孔）
                            elif subobj.TypeId == 'PartDesign::SubtractiveCylinder':
                                # 使用对象ID作为唯一标识符
                                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
                                
                                # 如果这个对象已经处理过，跳过
                                if obj_id in processed_objects:
                                    continue
                                processed_objects.add(obj_id)
                                
                                if subobj.Shape.ShapeType == "Solid" and hasattr(subobj.Shape, "Volume"):
                                    # 直接从对象获取半径属性
                                    hole_radius = subobj.Radius.Value if hasattr(subobj, "Radius") else 0
                                    
                                    # 获取位置信息
                                    position = None
                                    if hasattr(subobj, "Placement") and hasattr(subobj.Placement, "Base"):
                                        position = {
                                            'x': subobj.Placement.Base.x,
                                            'y': subobj.Placement.Base.y,
                                            'z': subobj.Placement.Base.z
                                        }
                                    
                                    # 所有减料圆柱体都记录为孔，无需检查可见性
                                    holes.append({
                                        'radius': hole_radius,
                                        'position': position
                                    })
    
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
        'cylinder_radius': extract_value(main_cylinder['radius']) if main_cylinder else None,
        'cylinder_height': extract_value(main_cylinder['height']) if main_cylinder else None,
        'hole_radius': extract_value(holes[0]['radius']) if holes else None,
        'hole_count': len(holes)
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