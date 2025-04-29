// FreeCAD Sphere Creation Monitoring Hook Script
// Used to monitor FreeCAD's sphere creation operations and detect any queries
// After creating a sphere and saving the file, the test program listens for the save event and checks if a sphere exists in the corresponding document

(function() {
  // Script constants
  const FUNCTION_NAME = "_ZNK3App8Document10saveToFileEPKc"
  const ORIGIN_FUNCTION_NAME = "Document::saveToFile"
  const FUNCTION_BEHAVIOR = "document saving"

  const SCRIPT_INITIALIZED = "script_initialized"
  const FUNCTION_NOT_FOUND = "function_not_found"
  const FUNCTION_FOUND = "function_found"
  const FUNCTION_CALLED = "function_called"
  const FUNCTION_KEY_WORD_DETECTED = "function_key_word_detected"
  const ERROR = "error"
  const HOOK_INSTALLED = "hook_installed"

  const APP_NAME = "FreeCAD"
  
  let funcFound = false;
  
  function sendEvent(eventType, data = {}) {
      const payload = {
          event: eventType,
          ...data,
          timestamp: new Date().getTime()
      };
      send(payload);
  }
  
  function getFunction() {
      let FuncAddr = DebugSymbol.getFunctionByName(FUNCTION_NAME);
      if (!FuncAddr) {
          sendEvent(ERROR, {
              error_type: FUNCTION_NOT_FOUND,
              message: `Could not find ${ORIGIN_FUNCTION_NAME} function`
          });
          return null;
      }
      funcFound = true;
      sendEvent(FUNCTION_FOUND, {
          address: FuncAddr.toString(),
          message: `Found ${ORIGIN_FUNCTION_NAME} function`
      });
      return FuncAddr;
  }
  
  function initHook() {
      sendEvent(SCRIPT_INITIALIZED, {
          message: `${APP_NAME} ${FUNCTION_BEHAVIOR} monitoring script started`
      });
      const funcAddr = getFunction();
      if (!funcAddr) {
          return;
      }
      Interceptor.attach(funcAddr, {
          onEnter: function(args) {
              try {
                  sendEvent(FUNCTION_CALLED, {
                      message: `Intercepted ${FUNCTION_BEHAVIOR} function call`
                  });
                  this.filename = args[1].readCString();
              } catch (error) {
                  sendEvent(ERROR, {
                      error_type: "general_error",
                      message: `Execution error: ${error.message}`
                  });
              }
          },
          onLeave: function(retval) {
              try {
                if (retval) {
                    const pythonCode = `
import freecad
import FreeCAD
file_path = '${this.filename}'
doc = FreeCAD.open(file_path)
if doc is None:
    result = None
else:
    sphere = None
    for obj in reversed(doc.Objects):
        if "Sphere" in obj.TypeId:
            sphere = obj
            break
    if sphere is None:
        result = None
    else:
        result = {
            "radius": sphere.Radius.Value
        }
                    `
                    sendEvent(FUNCTION_KEY_WORD_DETECTED, {
                        message: `Detected ${FUNCTION_BEHAVIOR} operation`,
                        filename: this.filename,
                        code: pythonCode
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
  initHook();
})();
