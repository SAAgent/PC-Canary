// FreeCAD Regular Polygon Monitoring Hook Script
// Used to monitor FreeCAD's regular polygon creation operation and detect task completion
// After creating a regular polygon and saving the file, the test program listens for the save and checks if there is a regular polygon meeting the requirements in the corresponding document

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
    polygon = None
    
    # Check all objects, look for regular polygons
    for obj in doc.Objects:
        if obj.TypeId == "Sketcher::SketchObject":
            sketch = obj
            
            # Get the number of geometric figures
            if hasattr(sketch, "Geometry") and len(sketch.Geometry) > 0:
                # Check if it could be a regular polygon
                lines = [g for g in sketch.Geometry if g.TypeId == 'Part::GeomLineSegment']
                
                # Get constraints
                constraints = sketch.Constraints if hasattr(sketch, "Constraints") else []
                
                # Look for equal length and equal angle constraints, which are characteristics of regular polygons
                equal_constraints = [c for c in constraints if c.Type == "Equal"]
                angle_constraints = [c for c in constraints if c.Type == "Angle"]
                
                # If there are 3 or more line segments and equal constraints, it might be a regular polygon
                if len(lines) >= 3 and len(equal_constraints) >= 1:
                    # Calculate number of sides of the polygon
                    sides = len(lines)
                    
                    # Extract endpoints of all line segments
                    vertices = []
                    for line in lines:
                        if hasattr(line, "StartPoint"):
                            vertices.append((line.StartPoint.x, line.StartPoint.y))
                        if hasattr(line, "EndPoint"):
                            vertices.append((line.EndPoint.x, line.EndPoint.y))
                    
                    # If there are enough vertices
                    if len(vertices) >= sides:
                        # Calculate radius as average distance from vertices to center
                        # First calculate polygon center (average of vertex positions)
                        center_x = sum(v[0] for v in vertices) / len(vertices)
                        center_y = sum(v[1] for v in vertices) / len(vertices)
                        
                        # Calculate distance from each vertex to center
                        radii = []
                        for vx, vy in vertices:
                            dx = vx - center_x
                            dy = vy - center_y
                            distance = (dx**2 + dy**2)**0.5
                            radii.append(distance)
                        
                        # Calculate average radius
                        avg_radius = sum(radii) / len(radii)
                        
                        # If all radii are approximately equal (within 0.05%), it's likely a regular polygon
                        is_regular = all(abs(r - avg_radius) / avg_radius < 0.0005 for r in radii)
                        
                        if is_regular:
                            polygon = {
                                "sides": sides,
                                "radius": avg_radius
                            }
                            break
    
    result = polygon
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
          message: `Hook installed, waiting for ${FUNCTION_BEHAVIOR} operation...`
      });
  }
  
  // Execute hook initialization immediately
  initHook();
})();