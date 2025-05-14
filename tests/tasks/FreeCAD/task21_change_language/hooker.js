// FreeCAD Language Switching Monitoring Hook Script
// Used to monitor language switching operations in FreeCAD

(function() {
  // Script constants setup
  const FUNCTION_NAME = "_ZN3Gui10Translator16activateLanguageEPKc"
  const ORIGIN_FUNCTION_NAME = "Translator::activateLanguage"
  const FUNCTION_BEHAVIOR = "language switch"

  const SCRIPT_INITIALIZED = "script_initialized"
  const FUNCTION_NOT_FOUND = "function_not_found"
  const FUNCTION_FOUND = "function_found"
  const FUNCTION_CALLED = "function_called"
  const FIRST_LANGUAGE_SET = "first_language_set"
  const FINAL_LANGUAGE_SET = "final_language_set"
  const ERROR = "error"
  const HOOK_INSTALLED = "hook_installed"

  const APP_NAME = "FreeCAD"
  
  // Global variables
  let funcFound = false;
  let firstLanguageDetected = false;
  let firstLanguage = "Chinese Simplified";  // Expected first language
  let finalLanguage = "English";  // Expected final language
  
  // Send events to the evaluation system
  function sendEvent(eventType, data = {}) {
      const payload = {
          event: eventType,
          ...data,
          timestamp: new Date().getTime()
      };
      send(payload);
  }
  
  // Find Translator::activateLanguage function
  function getFunction() {
      // Try to find directly through export symbols
      let FuncAddr = DebugSymbol.getFunctionByName(FUNCTION_NAME);
      
      // If not found, report error
      if (!FuncAddr) {
          sendEvent(ERROR, {
              error_type: FUNCTION_NOT_FOUND,
              message: `Could not find ${ORIGIN_FUNCTION_NAME} function`
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
      
      // Find language switching function
      const funcAddr = getFunction();
      if (!funcAddr) {
          return;
      }
      
      // Install language switching function hook
      Interceptor.attach(funcAddr, {
          onEnter: function(args) {
              try {
                  sendEvent(FUNCTION_CALLED, {
                      message: `Intercepted ${FUNCTION_BEHAVIOR} function call`
                  });
                  this.language = args[1].readCString();
              } catch (error) {
                  sendEvent(ERROR, {
                      error_type: "general_error",
                      message: `Execution error: ${error.message}`
                  });
              }
          },

          onLeave: function(retval) {
              try {
                  // Check if this is the first time setting to Chinese
                  if (this.language === firstLanguage && !firstLanguageDetected) {
                      firstLanguageDetected = true;
                      sendEvent(FIRST_LANGUAGE_SET, {
                          message: `Detected first ${FUNCTION_BEHAVIOR} operation`,
                          language: this.language
                      });
                  }
                  // Check if this is the final setting to English
                  else if (this.language === finalLanguage && firstLanguageDetected) {
                      sendEvent(FINAL_LANGUAGE_SET, {
                          message: `Detected final ${FUNCTION_BEHAVIOR} operation`,
                          language: this.language
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
          message: `Hook installation complete, waiting for ${FUNCTION_BEHAVIOR} operations...`
      });
  }
  
  // Execute hook initialization immediately
  initHook();
})();
