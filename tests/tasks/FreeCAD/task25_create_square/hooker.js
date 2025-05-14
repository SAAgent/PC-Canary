// FreeCAD Square Creation Monitoring Hook Script
// Used to monitor square creation operations in FreeCAD and detect any queries
// After creating the square and saving the file, the test program detects whether a square exists in the saved document

(function() {
  // Script constants
  const FUNCTION_NAME = "_ZNK3App8Document10saveToFileEPKc"
  const ORIGIN_FUNCTION_NAME = "Document::saveToFile"
  const FUNCTION_BEHAVIOR = "save document"

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
  
  // Find Document::saveToFile function
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
      
      // Find target function
      const funcAddr = getFunction();
      if (!funcAddr) {
          return;
      }
      
      // Install search function hook
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
    # Open document
    if os.path.exists("${this.filename}"):
        doc = FreeCAD.openDocument("${this.filename}")
        
        # Find square object
        square_found = False
        for obj in doc.Objects:
            # Check if object is a square
            if hasattr(obj, "Shape") and hasattr(obj.Shape, "Edges"):
                edges = obj.Shape.Edges
                if len(edges) == 4:
                    # Check if it's a square
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
    
        # Close document
        FreeCAD.closeDocument(doc.Name)
except Exception as e:
    print(f"Error: {str(e)}")
                    `;
                    
                    // Send keyword detection event
                    sendEvent(FUNCTION_KEY_WORD_DETECTED, {
                        message: `Detected ${FUNCTION_BEHAVIOR} operation`,
                        code: pythonCode,
                        filename: this.filename
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
