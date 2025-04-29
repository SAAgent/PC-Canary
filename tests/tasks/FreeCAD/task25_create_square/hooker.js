// FreeCAD创建正方形监控钩子脚本
// 用于监听FreeCAD的创建正方形操作并检测任何查询
// 创建正方形后保存文件，测试程序监听到保存后查询对应文档中是否存在正方形

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
      
      // 查找目标函数
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
import os
import freecad
import FreeCAD
import Part

result = {
    "side_length": 0,
    "center_x": 0,
    "center_y": 0,
    "has_square": False
}

try:
    # 打开文档
    if os.path.exists("${this.filename}"):
        doc = FreeCAD.openDocument("${this.filename}")
        
        # 查找正方形对象
        square_found = False
        for obj in doc.Objects:
            # 检查对象是否是正方形
            if hasattr(obj, "Shape") and hasattr(obj.Shape, "Edges"):
                edges = obj.Shape.Edges
                if len(edges) == 4:
                    # 检查是否为正方形
                    lengths = [edge.Length for edge in edges]
                    if all(abs(length - lengths[0]) < 0.01 for length in lengths):
                        square_found = True
                        result["side_length"] = lengths[0]
                        result["center_x"] = obj.Shape.BoundBox.Center.x
                        result["center_y"] = obj.Shape.BoundBox.Center.y
                        result["has_square"] = True
                        break
                    
                if square_found:
                    break
    
        # 关闭文档
        FreeCAD.closeDocument(doc.Name)
except Exception as e:
    print(f"Error: {str(e)}")
                    `;
                    
                    // 发送关键字检测事件
                    sendEvent(FUNCTION_KEY_WORD_DETECTED, {
                        message: `检测到${FUNCTION_BEHAVIOR}操作`,
                        code: pythonCode,
                        filename: this.filename
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
