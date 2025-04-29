// FreeCAD创建带中心圆孔的正八边形棱柱监控钩子脚本
// 用于监听FreeCAD的创建带中心圆孔的正八边形棱柱操作并检测任务完成情况
// 创建带中心圆孔的正八边形棱柱后保存文件，测试程序监听到保存后查询对应文档中是否存在符合要求的带中心圆孔的正八边形棱柱

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
    # 查找正八边形棱柱和中心孔
    prism = None
    hole = None
    has_hole = False
    hole_radius = 0.0
    sides_count = 0
    
    # 检查所有对象，寻找棱柱和孔
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
                            # 寻找多边形棱柱
                            if ('Prism' in subobj.TypeId or 'Extrusion' in subobj.TypeId 
                                or 'Pad' in subobj.TypeId or 'AdditivePrism' in subobj.TypeId):
                                # 使用对象ID作为唯一标识符
                                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
                                
                                # 如果这个对象已经处理过，跳过
                                if obj_id in processed_objects:
                                    continue
                                processed_objects.add(obj_id)
                                
                                if subobj.Shape.ShapeType == "Solid":
                                    # 尝试获取棱柱参数
                                    if hasattr(subobj, "Polygon"):
                                        # 如果是多边形棱柱，获取边数
                                        sides_count = subobj.Polygon
                                    elif hasattr(subobj, "Circumradius"):
                                        # 获取外接圆半径
                                        prism_radius = subobj.Circumradius.Value
                                    elif hasattr(subobj, "Height"):
                                        # 获取高度
                                        prism_height = subobj.Height.Value
                                    elif hasattr(subobj, "Length"):
                                        # 对于某些情况，长度可能代表高度
                                        prism_height = subobj.Length.Value
                                    
                                    # 如果参数获取不完整，通过形状进行分析
                                    if sides_count == 0:
                                        # 尝试通过形状识别边数
                                        if hasattr(subobj.Shape, "Faces"):
                                            # 对于棱柱，应该有边数+2个面（底面、顶面和侧面）
                                            face_count = len(subobj.Shape.Faces)
                                            if face_count >= 3:  # 至少三个面
                                                # 侧面数量可能代表多边形边数
                                                possible_sides = face_count - 2
                                                if possible_sides >= 3:  # 至少是三角形
                                                    sides_count = possible_sides
                            
                            # 检查是否有中心孔
                            elif ('Pocket' in subobj.TypeId or 'SubtractiveCylinder' in subobj.TypeId 
                                  or 'Cut' in subobj.TypeId or 'Hole' in subobj.TypeId):
                                # 使用对象ID作为唯一标识符
                                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
                                
                                # 如果这个对象已经处理过，跳过
                                if obj_id in processed_objects:
                                    continue
                                processed_objects.add(obj_id)
                                
                                # 标记存在孔
                                has_hole = True
                                
                                # 尝试获取孔半径
                                if hasattr(subobj, "Radius"):
                                    hole_radius = subobj.Radius.Value
                                elif hasattr(subobj, "Diameter"):
                                    hole_radius = subobj.Diameter.Value / 2
    
    # 如果通过属性获取不到完整信息，尝试通过几何分析
    # 计算棱柱的外接圆半径和高度
    if not prism:
        prism_radius = 0.0
        prism_height = 0.0
        
        # 遍历文档中的所有对象
        for obj in doc.Objects:
            if hasattr(obj, "Shape") and hasattr(obj.Shape, "BoundBox"):
                # 获取边界盒
                bbox = obj.Shape.BoundBox
                
                # 计算X-Y平面的外接圆半径
                center_x = (bbox.XMin + bbox.XMax) / 2
                center_y = (bbox.YMin + bbox.YMax) / 2
                
                # 找出最远的顶点，作为外接圆半径
                max_radius = 0.0
                
                if hasattr(obj.Shape, "Vertexes"):
                    for vertex in obj.Shape.Vertexes:
                        dx = vertex.X - center_x
                        dy = vertex.Y - center_y
                        distance = math.sqrt(dx*dx + dy*dy)
                        max_radius = max(max_radius, distance)
                
                if max_radius > 0:
                    prism_radius = max_radius
                
                # 高度通常是Z方向的尺寸
                prism_height = bbox.ZMax - bbox.ZMin
                
                # 验证是否可能是八边形棱柱
                if hasattr(obj.Shape, "Faces") and sides_count == 0:
                    # 计算面的数量
                    face_count = len(obj.Shape.Faces)
                    # 棱柱应有边数+2个面
                    if face_count >= 5:  # 至少是三角棱柱（5个面）
                        sides_count = face_count - 2
    
    # 验证中心孔 - 检查孔是否接近中心
    if not has_hole:
        # 尝试通过几何方式检测中心孔
        for obj in doc.Objects:
            if hasattr(obj, "Shape") and hasattr(obj.Shape, "Faces"):
                # 寻找圆柱形内表面，可能是孔
                for face in obj.Shape.Faces:
                    if hasattr(face, "Surface") and hasattr(face.Surface, "Radius"):
                        # 找到一个圆柱面
                        potential_hole_radius = face.Surface.Radius
                        
                        # 检查该面是否在物体中心附近
                        if hasattr(face, "CenterOfMass"):
                            center_of_mass = face.CenterOfMass
                            # 检查该面的中心是否接近物体中心(XY平面)
                            if abs(center_of_mass.x) < 1.0 and abs(center_of_mass.y) < 1.0:
                                has_hole = True
                                hole_radius = potential_hole_radius
                                break
    
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
        'prism_radius': extract_value(prism_radius),
        'prism_height': extract_value(prism_height),
        'hole_radius': extract_value(hole_radius),
        'sides_count': sides_count,
        'has_hole': has_hole
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
