// FreeCAD create rounded rectangle monitoring hook script
// Used to listen to FreeCAD's create rounded rectangle operation and detect task completion
// After creating a rounded rectangle, save the file. The test program listens for the save and queries the corresponding document for a rounded rectangle that meets the requirements.

(function() {
  // Script constant settings
  const FUNCTION_NAME = "_ZNK3App8Document10saveToFileEPKc"
  const ORIGIN_FUNCTION_NAME = "Document::saveToFile"
  const FUNCTION_BEHAVIOR = "Save Document"

  const SCRIPT_INITIALIZED = "script_initialized"
  const FUNCTION_NOT_FOUND = "function_not_found"
  const FUNCTION_FOUND = "function_found"
  const FUNCTION_CALLED = "function_called"
  const FUNCTION_KEY_WORD_DETECTED = "function_key_word_detected"
  const ERROR = "error"
  const HOOK_INSTALLED = "hook_installed"

  const APP_NAME = "FreeCAD"
  
  // Global variable
  let funcFound = false;
  
  // Send event to the evaluation system
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
      
      // If not found, report an error
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
import Part

# Open the specified file
file_path = '${this.filename}'
doc = FreeCAD.open(file_path)

# Get active document
if doc is None:
    result = None
else:
    # Find shapes in the document
    rounded_rect = None
    
    # Check all objects, look for rounded rectangles
    # In Sketch, rounded rectangles are usually composed of multiple geometric elements
    for obj in doc.Objects:
        if obj.TypeId == "Sketcher::SketchObject":
            sketch = obj
            
            # Get the number of geometric figures, rounded rectangles are usually composed of straight lines and arcs
            # Simple rounded rectangles usually have 8 geometric elements: 4 straight lines and 4 arcs
            if hasattr(sketch, "Geometry") and len(sketch.Geometry) >= 8:
                # Basic properties of a rounded rectangle
                lines = [g for g in sketch.Geometry if g.TypeId == 'Part::GeomLineSegment']
                arcs = [g for g in sketch.Geometry if g.TypeId == 'Part::GeomArcOfCircle']
                
                # Simple check: rounded rectangles usually have 4 lines and 4 arcs
                if len(lines) >= 4 and len(arcs) >= 4:
                    # Simple estimation of rectangle size (calculate bounding box)
                    vertices = []
                    
                    # Get endpoints of curves
                    for line in lines:
                        vertices.append((line.StartPoint.x, line.StartPoint.y))
                        vertices.append((line.EndPoint.x, line.EndPoint.y))
                    
                    # If there are enough points to form a bounding box
                    if len(vertices) >= 4:
                        xs = [v[0] for v in vertices]
                        ys = [v[1] for v in vertices]
                        
                        # Calculate bounding box dimensions
                        length = max(xs) - min(xs)
                        width = max(ys) - min(ys)
                        
                        # Estimate radius (take the average of arc radii)
                        radius = 0
                        if arcs:
                            radius = sum([arc.Radius for arc in arcs]) / len(arcs)
                        
                        # Set result
                        rounded_rect = {
                            "length": abs(length),
                            "width": abs(width),
                            "radius": radius
                        }
                        break
    
    result = rounded_rect
                    `
                    sendEvent(FUNCTION_KEY_WORD_DETECTED, {
                        message: `Detected ${FUNCTION_BEHAVIOR} operation`,
                        filename: this.filename,
                        code: pythonCode
                    });
                }
                // Detect keyword
              } catch (error) {
                  sendEvent(ERROR, {
                      error_type: "general_error",
                      message: `Execution error: ${error.message}`
                  });
              }
          }
      });
      
      sendEvent(HOOK_INSTALLED, {
          message: `Hook installed, waiting for ${FUNCTION_BEHAVIOR} operation...`
      });
  }
  
  // Execute hook initialization immediately
  initHook();
})();