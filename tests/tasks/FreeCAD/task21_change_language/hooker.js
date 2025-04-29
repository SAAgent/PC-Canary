// FreeCAD语言切换监控钩子脚本
// 用于监听FreeCAD的语言切换操作

(function() {
  // 脚本常量设置
  const FUNCTION_NAME = "_ZN3Gui10Translator16activateLanguageEPKc"
  const ORIGIN_FUNCTION_NAME = "Translator::activateLanguage"
  const FUNCTION_BEHAVIOR = "切换语言"

  const SCRIPT_INITIALIZED = "script_initialized"
  const FUNCTION_NOT_FOUND = "function_not_found"
  const FUNCTION_FOUND = "function_found"
  const FUNCTION_CALLED = "function_called"
  const FIRST_LANGUAGE_SET = "first_language_set"
  const FINAL_LANGUAGE_SET = "final_language_set"
  const ERROR = "error"
  const HOOK_INSTALLED = "hook_installed"

  const APP_NAME = "FreeCAD"
  
  // 全局变量
  let funcFound = false;
  let firstLanguageDetected = false;
  let firstLanguage = "Chinese Simplified";  // 预期的第一个语言
  let finalLanguage = "English";  // 预期的最终语言
  
  // 向评估系统发送事件
  function sendEvent(eventType, data = {}) {
      const payload = {
          event: eventType,
          ...data,
          timestamp: new Date().getTime()
      };
      send(payload);
  }
  
  // 查找Translator::activateLanguage函数
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
      
      // 查找语言切换函数
      const funcAddr = getFunction();
      if (!funcAddr) {
          return;
      }
      
      // 安装语言切换函数钩子
      Interceptor.attach(funcAddr, {
          onEnter: function(args) {
              try {
                  sendEvent(FUNCTION_CALLED, {
                      message: `拦截到${FUNCTION_BEHAVIOR}函数调用`
                  });
                  this.language = args[1].readCString();
              } catch (error) {
                  sendEvent(ERROR, {
                      error_type: "general_error",
                      message: `执行错误: ${error.message}`
                  });
              }
          },

          onLeave: function(retval) {
              try {
                  // 检测是否是第一次设置为中文
                  if (this.language === firstLanguage && !firstLanguageDetected) {
                      firstLanguageDetected = true;
                      sendEvent(FIRST_LANGUAGE_SET, {
                          message: `检测到第一次${FUNCTION_BEHAVIOR}操作`,
                          language: this.language
                      });
                  }
                  // 检测是否是最终设置为英文
                  else if (this.language === finalLanguage && firstLanguageDetected) {
                      sendEvent(FINAL_LANGUAGE_SET, {
                          message: `检测到最终${FUNCTION_BEHAVIOR}操作`,
                          language: this.language
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
