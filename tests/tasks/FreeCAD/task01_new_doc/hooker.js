// FreeCAD创建新文档监控钩子脚本
// 用于监听FreeCAD的创建新文档操作

(function() {
  // 脚本常量设置
  const FUNCTION_NAME = "_ZN3App11Application11newDocumentEPKcS2_bb"
  const ORIGIN_FUNCTION_NAME = "Application::newDocument"
  const FUNCTION_BEHAVIOR = "创建新文档"

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
  
  // 查找MainWindow::newProject函数
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
  
  // 读取C++标准字符串内容
  function readCXXStdString(Ptr) {
      const str_ptr = Ptr;
      const len = str_ptr.add(0x8).readU64();
      const str = str_ptr.readPointer().readCString(len)
      return str;
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
              } catch (error) {
                  sendEvent(ERROR, {
                      error_type: "general_error",
                      message: `执行错误: ${error.message}`
                  });
              }
          },

          onLeave: function(retval) {
              try {
                  let Label = retval.add(0xB8)
                  let FileName = Label.add(0x60)

                  let LabelCXXStringPtr = Label.add(0x40)
                  let FileNameCXXStringPtr = FileName.add(0x40)

                  Label = readCXXStdString(LabelCXXStringPtr)
                  FileName = readCXXStdString(FileNameCXXStringPtr)
                  sendEvent(FUNCTION_KEY_WORD_DETECTED, {
                      message: `检测到${FUNCTION_BEHAVIOR}操作`,
                      label: Label,
                      filename: FileName
                  });
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