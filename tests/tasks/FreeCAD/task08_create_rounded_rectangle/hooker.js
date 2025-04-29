// FreeCAD创建圆角矩形监控钩子脚本
// 用于监听FreeCAD的创建圆角矩形操作并检测任务完成情况
// 创建圆角矩形后保存文件，测试程序监听到保存后查询对应文档中是否存在符合要求的圆角矩形

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
    rounded_rect = None
    
    # 检查所有对象，寻找圆角矩形
    # 在Sketch中圆角矩形通常由多个几何元素组成
    for obj in doc.Objects:
        if obj.TypeId == "Sketcher::SketchObject":
            sketch = obj
            
            # 获取几何图形数量，圆角矩形通常由直线和圆弧组成
            # 简单的圆角矩形通常有8个几何元素：4条直线和4个圆弧
            if hasattr(sketch, "Geometry") and len(sketch.Geometry) >= 8:
                # 圆角矩形的基本属性
                lines = [g for g in sketch.Geometry if g.TypeId == 'Part::GeomLineSegment']
                arcs = [g for g in sketch.Geometry if g.TypeId == 'Part::GeomArcOfCircle']
                
                # 简单检查：圆角矩形通常有4条线和4个圆弧
                if len(lines) >= 4 and len(arcs) >= 4:
                    # 简单估算矩形尺寸（计算边界框）
                    vertices = []
                    
                    # 获取曲线的端点
                    for line in lines:
                        vertices.append((line.StartPoint.x, line.StartPoint.y))
                        vertices.append((line.EndPoint.x, line.EndPoint.y))
                    
                    # 如果有足够的点来形成边界框
                    if len(vertices) >= 4:
                        xs = [v[0] for v in vertices]
                        ys = [v[1] for v in vertices]
                        
                        # 计算边界框尺寸
                        length = max(xs) - min(xs)
                        width = max(ys) - min(ys)
                        
                        # 估算半径（取圆弧半径的平均值）
                        radius = 0
                        if arcs:
                            radius = sum([arc.Radius for arc in arcs]) / len(arcs)
                        
                        # 设置结果
                        rounded_rect = {
                            "length": abs(length),
                            "width": abs(width),
                            "radius": radius
                        }
                        break
    
    result = rounded_rect
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