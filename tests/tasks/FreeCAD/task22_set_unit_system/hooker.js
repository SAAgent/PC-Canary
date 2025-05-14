// FreeCAD Unit System Setting Monitoring Hook Script
// Used to monitor unit system setting operations in FreeCAD

(function() {
  // Script constants
  const FUNCTION_NAME = "_ZN4Base8UnitsApi9setSchemaENS_10UnitSystemE"
  const ORIGIN_FUNCTION_NAME = "Base::UnitsApi::setSchema"
  const FUNCTION_BEHAVIOR = "set unit system"

  const SCRIPT_INITIALIZED = "script_initialized"
  const FUNCTION_NOT_FOUND = "function_not_found"
  const FUNCTION_FOUND = "function_found"
  const FUNCTION_CALLED = "function_called"
  const FIRST_UNIT_SYSTEM_SET = "first_unit_system_set"
  const FINAL_UNIT_SYSTEM_SET = "final_unit_system_set"
  const ERROR = "error"
  const HOOK_INSTALLED = "hook_installed"

  const APP_NAME = "FreeCAD"
  
  // Global variables
  let funcFound = false;
  let firstUnitSystemDetected = false;
  let firstUnitSystem = 3;  // Expected first unit system value
  let finalUnitSystem = 0;  // Expected final unit system value
  
  // Send event to evaluation system
  function sendEvent(eventType, data = {}) {
      const payload = {
          event: eventType,
          ...data,
          timestamp: new Date().getTime()
      };
      send(payload);
  }
  
  // Find Base::UnitsApi::setSchema function
  function getFunction() {
      // Try to find directly through exported symbol
      let FuncAddr = DebugSymbol.getFunctionByName(FUNCTION_NAME);
      
      // If not found, report error
      if (!FuncAddr) {
          sendEvent(ERROR, {
              error_type: FUNCTION_NOT_FOUND,
              message: `Cannot find ${ORIGIN_FUNCTION_NAME} function`
          });
          return null;
      }
      
      // Report function found
      funcFound = true;
      sendEvent(FUNCTION_FOUND, {
          address: FuncAddr.toString(),
          message: `Found ${ORIGIN_FUNCTION_NAME} function`
      });
      
      return FuncAddr;
  }
  
  // Initialize hook and execute immediately
  function initHook() {
      sendEvent(SCRIPT_INITIALIZED, {
          message: `${APP_NAME} ${FUNCTION_BEHAVIOR} monitoring script started`
      });
      
      // Find unit system setting function
      const funcAddr = getFunction();
      if (!funcAddr) {
          return;
      }
      
      // Install unit system setting function hook
      Interceptor.attach(funcAddr, {
          onEnter: function(args) {
              try {
                  sendEvent(FUNCTION_CALLED, {
                      message: `Intercepted ${FUNCTION_BEHAVIOR} function call`
                  });
                  // args[0] is this pointer, args[1] is unit system enum value
                  this.unitSystem = parseInt(args[1]);
              } catch (error) {
                  sendEvent(ERROR, {
                      error_type: "general_error",
                      message: `Execution error: ${error.message}`
                  });
              }
          },

          onLeave: function(retval) {
              try {
                  // Detect if this is the first setting to 3
                  if (this.unitSystem === firstUnitSystem && !firstUnitSystemDetected) {
                      firstUnitSystemDetected = true;
                      sendEvent(FIRST_UNIT_SYSTEM_SET, {
                          message: `Detected first ${FUNCTION_BEHAVIOR} operation`,
                          unit_system: this.unitSystem
                      });
                  }
                  // Detect if this is the final setting to 0
                  else if (this.unitSystem === finalUnitSystem && firstUnitSystemDetected) {
                      sendEvent(FINAL_UNIT_SYSTEM_SET, {
                          message: `Detected final ${FUNCTION_BEHAVIOR} operation`,
                          unit_system: this.unitSystem
                      });
                  }
              } catch (error) {
                  sendEvent(ERROR, {
                      error_type: "general_error",
                      message: `Execution error: ${error.message}`
                  });
              }
          }
      });
      
      sendEvent(HOOK_INSTALLED, {
          message: `Hook installation complete, waiting for ${FUNCTION_BEHAVIOR} operation...`
      });
  }
  
  // 立即执行钩子初始化
  initHook();
})();
