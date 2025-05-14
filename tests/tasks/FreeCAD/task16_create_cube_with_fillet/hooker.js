// FreeCAD Cube with Fillets Monitoring Hook Script
// Used to monitor FreeCAD creation of a cube with fillets and detect task completion
// After creating a cube with fillets and saving the file, the test program listens for the save and checks if the corresponding document contains the required cube with fillets

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
    # Find cube and fillets
    cube = None
    fillet = None
    has_fillet = False
    fillet_radius = 0.0
    processed_objects = set()  # To track processed objects
    # Check all objects, looking for cube and fillets
    for subobj in doc.Objects:
        if hasattr(subobj, "Shape") and hasattr(subobj.Shape, "ShapeType"):
            # Use TypeId to check if it's an additive cube
            if subobj.TypeId == 'PartDesign::AdditiveBox' or subobj.TypeId == 'Part::Box':
                # Use object ID as a unique identifier
                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
                
                # If this object has already been processed, skip it
                if obj_id in processed_objects:
                    continue
                processed_objects.add(obj_id)
                
                if subobj.Shape.ShapeType == "Solid":
                    # Check if it's a cube, read properties directly
                    cube_length = subobj.Length.Value if hasattr(subobj, "Length") else 0
                    cube_width = subobj.Width.Value if hasattr(subobj, "Width") else 0
                    cube_height = subobj.Height.Value if hasattr(subobj, "Height") else 0
                    
                    # Store cube information
                    cube = {
                        'length': cube_length,
                        'width': cube_width,
                        'height': cube_height
                    }
            
            # Check if there are fillet features (could be multiple types)
            elif subobj.TypeId == 'PartDesign::Fillet' or 'Fillet' in subobj.TypeId:
                # Use object ID as a unique identifier
                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
                
                # If this object has already been processed, skip it
                if obj_id in processed_objects:
                    continue
                processed_objects.add(obj_id)
                
                # Mark that fillets exist
                has_fillet = True
                
                # Try to get the fillet radius
                if hasattr(subobj, "Radius"):
                    if isinstance(subobj.Radius, list):
                        # If it's a list, take the first value
                        if len(subobj.Radius) > 0:
                            fillet_radius = float(subobj.Radius[0])
                    else:
                        # Get value directly
                        fillet_radius = float(subobj.Radius)
                elif hasattr(subobj, "FilletRadius"):
                    fillet_radius = float(subobj.FilletRadius)
    
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
        'cube_length': extract_value(cube['length']) if cube else None,
        'cube_width': extract_value(cube['width']) if cube else None,
        'cube_height': extract_value(cube['height']) if cube else None,
        'fillet_radius': extract_value(fillet_radius),
        'has_fillet': has_fillet
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
