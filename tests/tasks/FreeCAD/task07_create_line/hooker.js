// FreeCAD Line Creation Monitoring Hook Script
// Used to monitor FreeCAD's line creation operations

(function() {
  // Script constant settings
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
  
  // Global variables
  let funcFound = false;
  
  // Send events to the evaluation system
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
      // Try to find directly through exported symbols
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
          message: `${APP_NAME} line creation monitoring script started`
      });
      
      // Find search function
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
import freecad
import FreeCAD
import math

# Open the specified file
file_path = '/FreeCAD/task07.FCStd'
doc = FreeCAD.open(file_path)

# Get active document
if doc is None:
    result = None
else:
    for obj in doc.Objects:
        # Find sketch object
        sketch = None
        if obj.TypeId == "Sketcher::SketchObject":
            sketch = obj
        if sketch is None:
            result = {
                "found": False,
                "message": "Sketch object not found"
            }
        else:
            # Check if sketch contains a line
            has_line = False
            line_length = 0.0
            
            # Iterate through geometries in the sketch
            for i in range(sketch.GeometryCount):
                geo = sketch.Geometry[i]
                if geo.TypeId == "Part::GeomLineSegment":
                    # Found a line
                    has_line = True
                    # Calculate line length
                    start = geo.StartPoint
                    end = geo.EndPoint
                    dx = end.x - start.x
                    dy = end.y - start.y
                    line_length = math.sqrt(dx*dx + dy*dy)
                    break
            
            if has_line:
                result = {
                    "found": True,
                    "has_line": True,
                    "length": line_length
                }
                break
            else:
                result = {
                    "found": True,
                    "has_line": False,
                    "message": "No line found in sketch"
            }

    print(result)
`
                    // Send keyword event containing Python code
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
          message: "Hook installation complete, waiting for line creation operation..."
      });
  }
  
  // Execute hook initialization immediately
  initHook();
})();