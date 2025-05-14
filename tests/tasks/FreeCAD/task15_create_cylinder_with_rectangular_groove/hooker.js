// FreeCAD Cylinder with Tilted Rectangular Groove Monitoring Hook Script
// Used to monitor FreeCAD creation of a cylinder with tilted rectangular groove and detect task completion
// After creating a cylinder with tilted rectangular groove and saving the file, the test program listens for the save and checks if the corresponding document contains the required cylinder with tilted rectangular groove

(function() {
  // Script constants setting
  const FUNCTION_NAME = "_ZNK3App8Document10saveToFileEPKc"
  const ORIGIN_FUNCTION_NAME = "Document::saveToFile"
  const FUNCTION_BEHAVIOR = "Document Save"

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
      // Try to find the function directly through exported symbols
      let FuncAddr = DebugSymbol.getFunctionByName(FUNCTION_NAME);
      
      // If not found, report error
      if (!FuncAddr) {
          sendEvent(ERROR, {
              error_type: FUNCTION_NOT_FOUND,
              message: `Unable to find ${ORIGIN_FUNCTION_NAME} function`
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
          message: `${APP_NAME} ${FUNCTION_BEHAVIOR} monitoring script has started`
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

# Get the active document
if doc is None:
    result = None
else:
    # Find cylinder and rectangular groove
    cylinder = None
    groove = None
    
    # Check all objects, looking for cylinder and rectangular groove
    for obj in doc.Objects:
        # Check if it's a solid object
        if hasattr(obj, "Shape"):
            # Check shape type
            if hasattr(obj.Shape, "ShapeType"):
                # For objects created with Part Design method, we need to check sub-objects
                if obj.TypeId == "PartDesign::Body":
                    # Prevent counting the same object multiple times
                    processed_objects = set()
                    
                    for subobj in obj.OutList:
                        if hasattr(subobj, "Shape") and hasattr(subobj.Shape, "ShapeType"):
                            # Use TypeId to check if it's an additive cylinder
                            if subobj.TypeId == 'PartDesign::AdditiveCylinder':
                                # Use object ID as a unique identifier
                                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
                                
                                # If this object has already been processed, skip it
                                if obj_id in processed_objects:
                                    continue
                                processed_objects.add(obj_id)
                                
                                if subobj.Shape.ShapeType == "Solid":
                                    # Check if it's a cylinder, read properties directly
                                    cylinder_radius = subobj.Radius.Value if hasattr(subobj, "Radius") else 0
                                    cylinder_height = subobj.Height.Value if hasattr(subobj, "Height") else 0
                                    
                                    # Store cylinder information
                                    cylinder = {
                                        'radius': cylinder_radius,
                                        'height': cylinder_height
                                    }
                            
                            # Use TypeId to check if it's a subtractive box (rectangular groove)
                            elif subobj.TypeId == 'PartDesign::SubtractiveBox':
                                # Use object ID as a unique identifier
                                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
                                
                                # If this object has already been processed, skip it
                                if obj_id in processed_objects:
                                    continue
                                processed_objects.add(obj_id)
                                
                                if subobj.Shape.ShapeType == "Solid":
                                    # Get basic properties of the rectangular groove
                                    # Height, width and depth of the rectangular groove
                                    groove_width = 0
                                    groove_height = 0
                                    groove_depth = 0
                                    groove_angle = 0
                                    
                                    # Try to extract from properties
                                    if hasattr(subobj, "Length"):
                                        groove_width = subobj.Length.Value
                                    if hasattr(subobj, "Height"):
                                        groove_height = subobj.Height.Value
                                    if hasattr(subobj, "Width"):
                                        groove_depth = subobj.Width.Value
                                    if hasattr(subobj, "Angle"):
                                        groove_angle = subobj.Angle
                                    
                                    # For box, get dimensions directly from the bounding box (if not already obtained)
                                    if hasattr(subobj, "Shape") and hasattr(subobj.Shape, "BoundBox"):
                                        bounds = subobj.Shape.BoundBox
                                        if groove_width == 0:
                                            groove_width = bounds.XLength
                                        if groove_height == 0:
                                            groove_height = bounds.ZLength
                                        if groove_depth == 0:
                                            groove_depth = bounds.YLength
                                    
                                    # Calculate tilt angle from placement position and angle (if not already obtained from properties)
                                    if groove_angle == 0 and hasattr(subobj, "Placement"):
                                        # Extract angle from rotation matrix
                                        if hasattr(subobj.Placement, "Rotation"):
                                            # Get rotation angle (in degrees)
                                            # In FreeCAD, rotation is usually expressed in radians
                                            rot_angle = subobj.Placement.Rotation.Angle * 180.0 / math.pi
                                            
                                            # Extract rotation around y-axis (usually the tilt angle)
                                            axis = subobj.Placement.Rotation.Axis
                                            if abs(axis.y) > 0.7:  # If rotation is mainly around Y axis
                                                groove_angle = rot_angle
                                            else:
                                                # Calculate angle with Y axis
                                                import math
                                                groove_angle = math.degrees(math.acos(axis.y))
                                                
                                    # Tilt angle could also be determined from position relative to cylinder
                                    # But we've already tried to get it from rotation
                                    
                                    # Store rectangular groove information
                                    groove = {
                                        'width': groove_width,
                                        'depth': groove_depth,
                                        'height': groove_height,
                                        'angle': groove_angle
                                    }
    
    # Return results - ensure we return pure numbers without units
    # Handle values that may have units
    def extract_value(val):
        if val is None:
            return None
        try:
            # If it's a string with unit (like "10.0 mm"), extract the numeric part
            if isinstance(val, str) and ' ' in val:
                return float(val.split()[0])
            # If it's a FreeCAD Quantity object, try to convert to float
            return float(val)
        except:
            # If conversion fails, return the original value
            return val
    
    result = {
        'cylinder_radius': extract_value(cylinder['radius']) if cylinder else None,
        'cylinder_height': extract_value(cylinder['height']) if cylinder else None,
        'groove_width': extract_value(groove['width']) if groove else None,
        'groove_depth': extract_value(groove['depth']) if groove else None,
        'groove_height': extract_value(groove['height']) if groove else None,
        'groove_angle': extract_value(groove['angle']) if groove else None,
        'has_groove': groove is not None
    }
                    `
                    sendEvent(FUNCTION_KEY_WORD_DETECTED, {
                        message: `Detected ${FUNCTION_BEHAVIOR} operation`,
                        filename: this.filename,
                        code: pythonCode
                    });
                }
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
