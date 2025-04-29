// FreeCAD创建正多边形监控钩子脚本
// 用于监听FreeCAD的创建正多边形操作并检测任务完成情况
// 创建正多边形后保存文件，测试程序监听到保存后查询对应文档中是否存在符合要求的正多边形

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

# 打开指定的文件
file_path = '${this.filename}'
doc = FreeCAD.open(file_path)

# 获取活动文档
if doc is None:
    result = None
else:
    # 查找文档中的形状
    polygon = None
    
    # 检查所有对象，寻找正多边形
    for obj in doc.Objects:
        if obj.TypeId == "Sketcher::SketchObject":
            sketch = obj
            
            # 获取几何图形数量
            if hasattr(sketch, "Geometry") and len(sketch.Geometry) > 0:
                # 检查是否可能是正多边形
                lines = [g for g in sketch.Geometry if g.TypeId == 'Part::GeomLineSegment']
                
                # 获取约束
                constraints = sketch.Constraints if hasattr(sketch, "Constraints") else []
                
                # 查找相等长度和等分角度的约束，这是正多边形的特征
                equal_constraints = [c for c in constraints if c.Type == "Equal"]
                angle_constraints = [c for c in constraints if c.Type == "Angle"]
                
                # 如果线段数量大于等于3且有相等约束，可能是正多边形
                if len(lines) >= 3 and len(equal_constraints) >= 1:
                    # 计算正多边形的边数
                    sides = len(lines)
                    
                    # 提取所有线段的端点
                    vertices = []
                    for line in lines:
                        if hasattr(line, "StartPoint"):
                            vertices.append((line.StartPoint.x, line.StartPoint.y))
                        if hasattr(line, "EndPoint"):
                            vertices.append((line.EndPoint.x, line.EndPoint.y))
                    
                    # 如果有足够的顶点
                    if len(vertices) >= sides:
                        # 计算所有顶点到中心的距离，取平均值作为外接圆半径
                        # 先计算多边形中心（顶点的平均位置）
                        center_x = sum(v[0] for v in vertices) / len(vertices)
                        center_y = sum(v[1] for v in vertices) / len(vertices)
                        
                        # 计算每个顶点到中心的距离
                        radii = []
                        for vx, vy in vertices:
                            dx = vx - center_x
                            dy = vy - center_y
                            distance = (dx**2 + dy**2)**0.5
                            radii.append(distance)
                        
                        # 计算平均半径
                        avg_radius = sum(radii) / len(radii)
                        
                        # 如果所有半径基本相等（差异在0.05%以内），则很可能是正多边形
                        is_regular = all(abs(r - avg_radius) / avg_radius < 0.0005 for r in radii)
                        
                        if is_regular:
                            polygon = {
                                "sides": sides,
                                "radius": avg_radius
                            }
                            break
    
    result = polygon
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