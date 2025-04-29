// FreeCAD单位系统设置监控钩子脚本
// 用于监听FreeCAD的单位系统设置操作

(function() {
  // 脚本常量设置
  const FUNCTION_NAME = "_ZN4Base8UnitsApi9setSchemaENS_10UnitSystemE"
  const ORIGIN_FUNCTION_NAME = "Base::UnitsApi::setSchema"
  const FUNCTION_BEHAVIOR = "设置单位系统"

  const SCRIPT_INITIALIZED = "script_initialized"
  const FUNCTION_NOT_FOUND = "function_not_found"
  const FUNCTION_FOUND = "function_found"
  const FUNCTION_CALLED = "function_called"
  const FIRST_UNIT_SYSTEM_SET = "first_unit_system_set"
  const FINAL_UNIT_SYSTEM_SET = "final_unit_system_set"
  const ERROR = "error"
  const HOOK_INSTALLED = "hook_installed"

  const APP_NAME = "FreeCAD"
  
  // 全局变量
  let funcFound = false;
  let firstUnitSystemDetected = false;
  let firstUnitSystem = 3;  // 预期的第一个单位系统值
  let finalUnitSystem = 0;  // 预期的最终单位系统值
  
  // 向评估系统发送事件
  function sendEvent(eventType, data = {}) {
      const payload = {
          event: eventType,
          ...data,
          timestamp: new Date().getTime()
      };
      send(payload);
  }
  
  // 查找Base::UnitsApi::setSchema函数
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
      
      // 查找单位系统设置函数
      const funcAddr = getFunction();
      if (!funcAddr) {
          return;
      }
      
      // 安装单位系统设置函数钩子
      Interceptor.attach(funcAddr, {
          onEnter: function(args) {
              try {
                  sendEvent(FUNCTION_CALLED, {
                      message: `拦截到${FUNCTION_BEHAVIOR}函数调用`
                  });
                  // args[0]是this指针，args[1]是单位系统的枚举值
                  this.unitSystem = parseInt(args[1]);
              } catch (error) {
                  sendEvent(ERROR, {
                      error_type: "general_error",
                      message: `执行错误: ${error.message}`
                  });
              }
          },

          onLeave: function(retval) {
              try {
                  // 检测是否是第一次设置为3
                  if (this.unitSystem === firstUnitSystem && !firstUnitSystemDetected) {
                      firstUnitSystemDetected = true;
                      sendEvent(FIRST_UNIT_SYSTEM_SET, {
                          message: `检测到第一次${FUNCTION_BEHAVIOR}操作`,
                          unit_system: this.unitSystem
                      });
                  }
                  // 检测是否是最终设置为0
                  else if (this.unitSystem === finalUnitSystem && firstUnitSystemDetected) {
                      sendEvent(FINAL_UNIT_SYSTEM_SET, {
                          message: `检测到最终${FUNCTION_BEHAVIOR}操作`,
                          unit_system: this.unitSystem
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
