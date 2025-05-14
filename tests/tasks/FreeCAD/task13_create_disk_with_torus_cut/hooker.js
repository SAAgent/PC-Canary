// FreeCAD Disk with Torus Groove Monitoring Hook Script
// Used to monitor the operation of creating a disk with a torus groove in FreeCAD and detect task completion
// After creating the disk with a torus groove, save the file. The test program listens for the save and queries the corresponding document to check if it contains the required disk with a torus groove

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

  // Find the Document::saveToFile function
  function getFunction() {
      // Attempt to find it directly via exported symbols
      let FuncAddr = DebugSymbol.getFunctionByName(FUNCTION_NAME);

      // If not found, report an error
      if (!FuncAddr) {
          sendEvent(ERROR, {
              error_type: FUNCTION_NOT_FOUND,
              message: `Unable to find the ${ORIGIN_FUNCTION_NAME} function`
          });
          return null;
      }

      // Report the function was found
      funcFound = true;
      sendEvent(FUNCTION_FOUND, {
          address: FuncAddr.toString(),
          message: `Found the ${ORIGIN_FUNCTION_NAME} function`
      });

      return FuncAddr;
  }

  // Initialize the hook and execute immediately
  function initHook() {
      sendEvent(SCRIPT_INITIALIZED, {
          message: `${APP_NAME} ${FUNCTION_BEHAVIOR} monitoring script has started`
      });

      // Find the target function
      const funcAddr = getFunction();
      if (!funcAddr) {
          return;
      }

      // Install the hook for the target function
      Interceptor.attach(funcAddr, {
          onEnter: function(args) {
              try {
                  sendEvent(FUNCTION_CALLED, {
                      message: `Intercepted a call to the ${FUNCTION_BEHAVIOR} function`
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
    # Find the disk and torus groove
    disk = None
    torus_cut = None

    # Check all objects to find the disk (cylinder) and torus groove (torus)
    for obj in doc.Objects:
        # Check if it is a solid object
        if hasattr(obj, "Shape"):
            # Check the shape type
            if hasattr(obj.Shape, "ShapeType"):
                # For objects created using Part Design, check sub-objects
                if obj.TypeId == "PartDesign::Body":
                    # Prevent duplicate counting of the same object
                    processed_objects = set()

                    for subobj in obj.OutList:
                        if hasattr(subobj, "Shape") and hasattr(subobj.Shape, "ShapeType"):
                            # Check if it is an additive cylinder (disk) using TypeId
                            if subobj.TypeId == 'PartDesign::AdditiveCylinder':
                                # Use object ID as a unique identifier
                                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name

                                # Skip if this object has already been processed
                                if obj_id in processed_objects:
                                    continue
                                processed_objects.add(obj_id)

                                if subobj.Shape.ShapeType == "Solid" and hasattr(subobj.Shape, "Volume"):
                                    # Check if it is a disk and directly read its properties
                                    disk_radius = subobj.Radius.Value if hasattr(subobj, "Radius") else 0
                                    disk_height = subobj.Height.Value if hasattr(subobj, "Height") else 0

                                    # Store disk information
                                    disk = {
                                        'radius': disk_radius,
                                        'height': disk_height
                                    }

                            # Check if it is a subtractive torus (torus groove) using TypeId
                            elif subobj.TypeId == 'PartDesign::SubtractiveTorus':
                                # Use object ID as a unique identifier
                                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name

                                # Skip if this object has already been processed
                                if obj_id in processed_objects:
                                    continue
                                processed_objects.add(obj_id)

                                if subobj.Shape.ShapeType == "Solid" and hasattr(subobj.Shape, "Volume"):
                                    # Directly get torus properties from the object
                                    torus_radius1 = subobj.Radius1.Value if hasattr(subobj, "Radius1") else 0
                                    torus_radius2 = subobj.Radius2.Value if hasattr(subobj, "Radius2") else 0
                                    torus_angle1 = subobj.Angle1 if hasattr(subobj, "Angle1") else 0
                                    torus_angle2 = subobj.Angle2 if hasattr(subobj, "Angle2") else 0
                                    torus_angle3 = subobj.Angle3 if hasattr(subobj, "Angle3") else 360

                                    # Store torus groove information
                                    torus_cut = {
                                        'radius1': torus_radius1,
                                        'radius2': torus_radius2,
                                        'angle1': torus_angle1,
                                        'angle2': torus_angle2,
                                        'angle3': torus_angle3
                                    }

    # Return the result - ensure pure numeric values without units
    # Handle values that may have units
    def extract_value(val):
        if val is None:
            return None
        try:
            # If it is a string with units (e.g., "10.0 mm"), extract the numeric part
            if isinstance(val, str) and ' ' in val:
                return float(val.split()[0])
            # If it is a FreeCAD Quantity object, try converting to float
            return float(val)
        except:
            # If conversion fails, return the original value
            return val

    result = {
    'disk_radius': extract_value(disk['radius']) if disk else None,
    'disk_height': extract_value(disk['height']) if disk else None,
    'torus_radius1': extract_value(torus_cut['radius1']) if torus_cut else None,
    'torus_radius2': extract_value(torus_cut['radius2']) if torus_cut else None,
    'torus_angle1': extract_value(torus_cut['angle1']) if torus_cut else None,
    'torus_angle2': extract_value(torus_cut['angle2']) if torus_cut else None,
    'torus_angle3': extract_value(torus_cut['angle3']) if torus_cut else None,
    'has_torus_cut': torus_cut is not None
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
          message: `Hook installed, waiting for ${FUNCTION_BEHAVIOR} operation...`
      });
  }

  // Execute hook initialization immediately
  initHook();
})();
