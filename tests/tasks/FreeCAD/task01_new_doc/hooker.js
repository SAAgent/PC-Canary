// FreeCAD New Document Monitoring Hook Script
// Used to monitor the creation of new documents in FreeCAD

(function() {
  // Script constants
  const FUNCTION_NAME = "_ZN3App11Application11newDocumentEPKcS2_bb"
  const ORIGIN_FUNCTION_NAME = "Application::newDocument"
  const FUNCTION_BEHAVIOR = "create new document"

  const SCRIPT_INITIALIZED = "script_initialized"
  const FUNCTION_NOT_FOUND = "function_not_found"
  const FUNCTION_FOUND = "function_found"
  const FUNCTION_CALLED = "function_called"
  const FUNCTION_KEY_WORD_DETECTED = "function_key_word_detected"
  const ERROR = "error"
  const HOOK_INSTALLED = "hook_installed"

  const APP_NAME = "FreeCAD"
  
  // Global variables
  let funcFound = false;
  
  // Send event to evaluation system
  function sendEvent(eventType, data = {}) {
      const payload = {
          event: eventType,
          ...data,
          timestamp: new Date().getTime()
      };
      send(payload);
  }
  
  // Find Application::newDocument function
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
  
  // Read C++ standard string content
  function readCXXStdString(Ptr) {
      const str_ptr = Ptr;
      const len = str_ptr.add(0x8).readU64();
      const str = str_ptr.readPointer().readCString(len)
      return str;
  }
  
  // Initialize hook and execute immediately
  function initHook() {
      sendEvent(SCRIPT_INITIALIZED, {
          message: `${APP_NAME} ${FUNCTION_BEHAVIOR} monitoring script started`
      });
      
      // Find target function
      const funcAddr = getFunction();
      if (!funcAddr) {
          return;
      }
      
      // Install function hook
      Interceptor.attach(funcAddr, {
          onEnter: function(args) {
              try {
                  sendEvent(FUNCTION_CALLED, {
                      message: `Intercepted ${FUNCTION_BEHAVIOR} function call`
                  });
              } catch (error) {
                  sendEvent(ERROR, {
                      error_type: "general_error",
                      message: `Execution error: ${error.message}`
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
                      message: `Detected ${FUNCTION_BEHAVIOR} operation`,
                      label: Label,
                      filename: FileName
                  });
                  // Detect keywords
                  
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