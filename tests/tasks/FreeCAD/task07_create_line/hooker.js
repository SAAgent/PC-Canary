// FreeCAD创建直线监控钩子脚本
// 用于监听FreeCAD的创建直线操作

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
          message: `${APP_NAME}创建直线监控脚本已启动`
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
import math

# 打开指定的文件
file_path = '/FreeCAD/task07.FCStd'
doc = FreeCAD.open(file_path)

# 获取活动文档
if doc is None:
    result = None
else:
    for obj in doc.Objects:
        # 查找草图对象
        sketch = None
        if obj.TypeId == "Sketcher::SketchObject":
            sketch = obj
        if sketch is None:
            result = {
                "found": False,
                "message": "未找到草图对象"
            }
        else:
            # 检查草图中是否有直线
            has_line = False
            line_length = 0.0
            
            # 遍历草图中的几何体
            for i in range(sketch.GeometryCount):
                geo = sketch.Geometry[i]
                if geo.TypeId == "Part::GeomLineSegment":
                    # 找到直线
                    has_line = True
                    # 计算直线长度
                    start = geo.StartPoint
                    end = geo.EndPoint
                    dx = end.x - start.x
                    dy = end.y - start.y
                    line_length = math.sqrt(dx*dx + dy*dy)
                    break
            
            if has_line:
                result = {
                    "found": True,
                    "has_line": True,
                    "length": line_length
                }
                break
            else:
                result = {
                    "found": True,
                    "has_line": False,
                    "message": "草图中未找到直线"
            }

    print(result)
`
                    // 发送包含Python代码的关键字事件
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
          message: "钩子安装完成，等待创建直线操作..."
      });
  }
  
  // 立即执行钩子初始化
  initHook();
})();