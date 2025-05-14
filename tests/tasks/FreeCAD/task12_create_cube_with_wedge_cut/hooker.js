// FreeCAD Cuboid with Wedge Cut Monitoring Hook Script
// Used to monitor FreeCAD's cuboid with wedge cut creation operation and detect task completion
// After creating a cuboid with wedge cut and saving the file, the test program listens for the save and checks if there is a cuboid with wedge cut meeting the requirements in the corresponding document

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

# Open specified file
file_path = '${this.filename}'
doc = FreeCAD.open(file_path)

# Get active document
if doc is None:
    result = None
else:
    # Find cuboid and wedge cut in the document
    main_cube = None
    wedge_cut = None
    
    # Check all objects, look for cuboid and wedge cut
    for obj in doc.Objects:
        # Check if it's a solid object
        if hasattr(obj, "Shape"):
            # Check shape type
            if hasattr(obj.Shape, "ShapeType"):
                # For objects created using Part Design method, we need to check sub-objects
                if obj.TypeId == "PartDesign::Body":
                    # Prevent counting the same object multiple times
                    processed_objects = set()
                    
                    for subobj in obj.OutList:
                        if hasattr(subobj, "Shape") and hasattr(subobj.Shape, "ShapeType"):
                            # Use TypeId to check if it's an additive box
                            if subobj.TypeId == 'PartDesign::AdditiveBox' or subobj.TypeId == 'Part::Box':
                                # Use object ID as unique identifier
                                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
                                
                                # Skip if this object has been processed
                                if obj_id in processed_objects:
                                    continue
                                processed_objects.add(obj_id)
                                
                                if subobj.Shape.ShapeType == "Solid" and hasattr(subobj.Shape, "Volume"):
                                    # Get cuboid dimensions
                                    cube_length = subobj.Length.Value if hasattr(subobj, "Length") else 0
                                    cube_width = subobj.Width.Value if hasattr(subobj, "Width") else 0
                                    cube_height = subobj.Height.Value if hasattr(subobj, "Height") else 0
                                    
                                    # Get position information
                                    cube_position = None
                                    if hasattr(subobj, "Placement") and hasattr(subobj.Placement, "Base"):
                                        cube_position = {
                                            'x': subobj.Placement.Base.x,
                                            'y': subobj.Placement.Base.y,
                                            'z': subobj.Placement.Base.z
                                        }
                                    
                                    # Store cuboid information
                                    main_cube = {
                                        'length': cube_length,
                                        'width': cube_width,
                                        'height': cube_height,
                                        'position': cube_position
                                    }
                            
                            # Use TypeId to check if it's a subtractive wedge
                            elif subobj.TypeId == 'PartDesign::SubtractiveWedge' or subobj.TypeId.endswith('::Wedge'):
                                # Use object ID as unique identifier
                                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
                                
                                # Skip if this object has been processed
                                if obj_id in processed_objects:
                                    continue
                                processed_objects.add(obj_id)
                                
                                if subobj.Shape.ShapeType == "Solid" and hasattr(subobj.Shape, "Volume"):
                                    # Get wedge parameters
                                    wedge_Xmin = subobj.Xmin.Value if hasattr(subobj, "Xmin") else 0.0
                                    wedge_Xmax = subobj.Xmax.Value if hasattr(subobj, "Xmax") else 0.0
                                    wedge_Ymin = subobj.Ymin.Value if hasattr(subobj, "Ymin") else 0.0
                                    wedge_Ymax = subobj.Ymax.Value if hasattr(subobj, "Ymax") else 0.0
                                    wedge_Zmin = subobj.Zmin.Value if hasattr(subobj, "Zmin") else 0.0
                                    wedge_Zmax = subobj.Zmax.Value if hasattr(subobj, "Zmax") else 0.0
                                    wedge_X2min = subobj.X2min.Value if hasattr(subobj, "X2min") else 0.0
                                    wedge_X2max = subobj.X2max.Value if hasattr(subobj, "X2max") else 0.0
                                    wedge_Z2min = subobj.Z2min.Value if hasattr(subobj, "Z2min") else 0.0
                                    wedge_Z2max = subobj.Z2max.Value if hasattr(subobj, "Z2max") else 0.0
                                    
                                    # Get position information
                                    wedge_position = None
                                    if hasattr(subobj, "Placement") and hasattr(subobj.Placement, "Base"):
                                        wedge_position = {
                                            'x': subobj.Placement.Base.x,
                                            'y': subobj.Placement.Base.y,
                                            'z': subobj.Placement.Base.z
                                        }
                                    
                                    # Store wedge information
                                    wedge_cut = {
                                        'Xmin': wedge_Xmin,
                                        'Xmax': wedge_Xmax,
                                        'Ymin': wedge_Ymin,
                                        'Ymax': wedge_Ymax,
                                        'Zmin': wedge_Zmin,
                                        'Zmax': wedge_Zmax,
                                        'X2min': wedge_X2min,
                                        'X2max': wedge_X2max,
                                        'Z2min': wedge_Z2min,
                                        'Z2max': wedge_Z2max,
                                        'position': wedge_position
                                    }
    
    # Handle values that might have units
    def extract_value(val):
        if val is None:
            return None
        try:
            # If it's a string with unit (like "10.0 mm"), extract the numeric part
            if isinstance(val, str) and ' ' in val:
                return float(val.split()[0])
            # If it's a FreeCAD Quantity object, try converting to float
            return float(val)
        except:
            # If conversion fails, return original value
            return val
    
    # Return result
    result = {
        'cube_length': extract_value(main_cube['length']) if main_cube else None,
        'cube_width': extract_value(main_cube['width']) if main_cube else None,
        'cube_height': extract_value(main_cube['height']) if main_cube else None,
        'wedge_Xmin': extract_value(wedge_cut['Xmin']) if wedge_cut else None,
        'wedge_Xmax': extract_value(wedge_cut['Xmax']) if wedge_cut else None,
        'wedge_Ymin': extract_value(wedge_cut['Ymin']) if wedge_cut else None,
        'wedge_Ymax': extract_value(wedge_cut['Ymax']) if wedge_cut else None,
        'wedge_Zmin': extract_value(wedge_cut['Zmin']) if wedge_cut else None,
        'wedge_Zmax': extract_value(wedge_cut['Zmax']) if wedge_cut else None,
        'wedge_X2min': extract_value(wedge_cut['X2min']) if wedge_cut else None,
        'wedge_X2max': extract_value(wedge_cut['X2max']) if wedge_cut else None,
        'wedge_Z2min': extract_value(wedge_cut['Z2min']) if wedge_cut else None,
        'wedge_Z2max': extract_value(wedge_cut['Z2max']) if wedge_cut else None,
        'has_wedge_cut': wedge_cut is not None
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
          message: `Hook installed, waiting for ${FUNCTION_BEHAVIOR} operation...`
      });
  }
  
  // Execute hook initialization immediately
  initHook();
})();
