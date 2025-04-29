// FreeCAD创建圆锥体监控钩子脚本
// 用于监听FreeCAD的创建圆锥体操作并检测任务完成情况
// 创建圆锥体后保存文件，测试程序监听到保存后查询对应文档中是否存在符合要求的圆锥体

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
    # 查找文档中的圆锥体
    cone = None
    
    # 检查所有对象，寻找圆锥体
    for obj in doc.Objects:
        # 检查是否是Part::Feature或相关类型对象
        if hasattr(obj, "TypeId") and "Part" in obj.TypeId:
            if hasattr(obj, "Shape") and hasattr(obj.Shape, "ShapeType"):
                # 检查对象是否有特定的形状类型
                if obj.Shape.ShapeType == "Solid":
                    faces = obj.Shape.Faces
                    
                    # 使用additive cone创建的圆锥体通常有2到3个面：顶面（小圆形或无）、底面（大圆形）和侧面
                    if len(faces) in [2, 3]:
                        # 查找是否有一个或两个圆形面和一个侧面
                        circle_faces = []
                        side_face = None
                        
                        for face in faces:
                            # 检查是否是平面
                            if face.Surface.TypeId == 'Part::GeomPlane':
                                # 检查是否是圆形
                                is_circle = True
                                radius = None
                                for edge in face.Edges:
                                    if edge.Curve.TypeId == 'Part::GeomCircle':
                                        radius = edge.Curve.Radius
                                        break
                                    else:
                                        is_circle = False
                                        break
                                
                                if is_circle and radius is not None:
                                    # 记录圆面的中心位置和半径
                                    center = face.Surface.Position
                                    circle_faces.append({
                                        "radius": radius,
                                        "center": center
                                    })
                            else:
                                # 可能是侧面
                                side_face = face
                        
                        # 如果找到一个或两个圆面和一个侧面，那么这很可能是一个圆锥体
                        if len(circle_faces) >= 1 and side_face is not None:
                            # 按照z坐标排序圆面，底面在下，顶面在上（如果存在）
                            circle_faces.sort(key=lambda x: x["center"].z)
                            bottom_face = circle_faces[0]
                            top_face = circle_faces[1] if len(circle_faces) > 1 else None
                            
                            # 计算底面半径、顶面半径（如果存在）和高度
                            bottom_radius = bottom_face["radius"]
                            top_radius = top_face["radius"] if top_face else 0
                            height = (top_face["center"].z - bottom_face["center"].z) if top_face else side_face.BoundBox.ZLength
                            
                            # 如果底面半径大于顶面半径，则认为这是一个圆锥（截头圆锥或标准圆锥）
                            if bottom_radius > top_radius and height > 0:
                                cone = {
                                    "radius": bottom_radius,
                                    "height": abs(height)
                                }
                                break
    
    result = cone
                    `
                    sendEvent(FUNCTION_KEY_WORD_DETECTED, {
                        message: `检测到${FUNCTION_BEHAVIOR}操作`,
                        filename: this.filename,
                        code: pythonCode
                    });
                }
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