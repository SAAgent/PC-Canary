// FreeCAD User Edit Mode Setting Monitoring Hook Script
// Used to monitor user edit mode setting operations in FreeCAD

(function() {
  // Script constants
  const FUNCTION_NAME = "_ZN3Gui11Application15setUserEditModeEi"
  const ORIGIN_FUNCTION_NAME = "Gui::Application::setUserEditMode"
  const FUNCTION_BEHAVIOR = "set user edit mode"

  const SCRIPT_INITIALIZED = "script_initialized"
  const FUNCTION_NOT_FOUND = "function_not_found"
  const FUNCTION_FOUND = "function_found"
  const FUNCTION_CALLED = "function_called"
  const FIRST_MODE_SET = "first_mode_set"
  const FINAL_MODE_SET = "final_mode_set"
  const ERROR = "error"
  const HOOK_INSTALLED = "hook_installed"

  const APP_NAME = "FreeCAD"
  
  // Global variables
  let funcFound = false;
  let firstModeDetected = false;
  let firstMode = 3;  // Expected first mode value
  let finalMode = 0;  // Expected final mode value
  
  // Send event to evaluation system
  function sendEvent(eventType, data = {}) {
      const payload = {
          event: eventType,
          ...data,
          timestamp: new Date().getTime()
      };
      send(payload);
  }
  
  // Find Gui::Application::setUserEditMode function
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
      
      // Find user edit mode setting function
      const funcAddr = getFunction();
      if (!funcAddr) {
          return;
      }
      
      // Install user edit mode setting function hook
      Interceptor.attach(funcAddr, {
          onEnter: function(args) {
              try {
                  sendEvent(FUNCTION_CALLED, {
                      message: `Intercepted ${FUNCTION_BEHAVIOR} function call`
                  });
                  // args[0] is this pointer, args[1] is user edit mode value
                  this.userEditMode = parseInt(args[1]);
                  this.isFirstMode = this.userEditMode === firstMode && !firstModeDetected;
                  this.isFinalMode = this.userEditMode === finalMode && firstModeDetected;
              } catch (error) {
                  sendEvent(ERROR, {
                      error_type: "general_error",
                      message: `Execution error: ${error.message}`
                  });
              }
          },

          onLeave: function(retval) {
              try {
                  // Detect if this is the first setting of expected mode
                  if (this.isFirstMode) {
                      firstModeDetected = true;
                      sendEvent(FIRST_MODE_SET, {
                          message: `Detected first ${FUNCTION_BEHAVIOR} operation`,
                          user_edit_mode: this.userEditMode
                      });
                  }
                  // Detect if this is the final setting of expected mode
                  else if (this.isFinalMode) {
                      sendEvent(FINAL_MODE_SET, {
                          message: `Detected final ${FUNCTION_BEHAVIOR} operation`,
                          user_edit_mode: this.userEditMode
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
  
  // Execute hook initialization immediately
  initHook();
})();
