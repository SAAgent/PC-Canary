// FreeCAD Cone Creation Monitoring Hook Script
// Used to monitor FreeCAD's cone creation operation and detect task completion
// After creating a cone and saving the file, the test program listens for the save and checks if there is a cone meeting the requirements in the corresponding document

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
import math

# Open the specified file
file_path = '${this.filename}'
doc = FreeCAD.open(file_path)

# Get active document
if doc is None:
    result = None
else:
    # Find cone in the document
    cone = None
    
    # Check all objects, look for cones
    for obj in doc.Objects:
        try:
            # Check if it's a Part::Feature or related type object
            if hasattr(obj, "TypeId") and "Part" in obj.TypeId:
                if hasattr(obj, "Shape") and hasattr(obj.Shape, "ShapeType"):
                    # Check if the object has a specific shape type
                    if obj.Shape.ShapeType == "Solid":
                        faces = obj.Shape.Faces
                        
                        # A cone created using additive cone typically has 2-3 faces: top face (small circle or none), bottom face (large circle), and side face
                        if len(faces) in [2, 3]:
                            # Look for one or two circular faces and one side face
                            circle_faces = []
                            side_face = None
                            
                            for face in faces:
                                # Check if it's a plane
                                if face.Surface.TypeId == 'Part::GeomPlane':
                                    # Check if it's circular
                                    is_circle = True
                                    radius = None
                                    for edge in face.Edges:
                                        if edge.Curve.TypeId == 'Part::GeomCircle':
                                            radius = edge.Curve.Radius
                                            break
                                        else:
                                            is_circle = False
                                            break
                                    
                                    if is_circle and radius is not None:
                                        # Record circle face center position and radius
                                        center = face.Surface.Position
                                        circle_faces.append({
                                            "radius": radius,
                                            "center": center
                                        })
                                else:
                                    # Might be a side face
                                    side_face = face
                            
                            # If we found one or two circular faces and one side face, it's likely a cone
                            if len(circle_faces) >= 1 and side_face is not None:
                                # Sort circular faces by z-coordinate, bottom face is lower, top face is higher (if exists)
                                circle_faces.sort(key=lambda x: x["center"].z)
                                bottom_face = circle_faces[0]
                                top_face = circle_faces[1] if len(circle_faces) > 1 else None
                                
                                # Calculate bottom radius, top radius (if exists), and height
                                bottom_radius = bottom_face["radius"]
                                top_radius = top_face["radius"] if top_face else 0
                                height = (top_face["center"].z - bottom_face["center"].z) if top_face else side_face.BoundBox.ZLength
                                
                                # If bottom radius is greater than top radius, consider it a cone (truncated or standard)
                                if bottom_radius > top_radius and height > 0:
                                    cone = {
                                        "radius": bottom_radius,
                                        "height": abs(height)
                                    }
                                    break
        except Exception as e:
            # Handle exception
            print(f"Error processing object {obj.Name}: {str(e)}")
            continue
    
    result = cone
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