// FreeCAD Cone with Hemispherical Cutout Monitoring Hook Script
// Monitors the creation of a cone with a hemispherical cutout in FreeCAD and checks task completion
// After creating the cone with a hemispherical cutout, save the file. The test program listens for the save event and queries the corresponding document to verify the presence of the required cone with a hemispherical cutout.

(function() {
  // Script constants
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

  // Locate the Document::saveToFile function
  function getFunction() {
      // Attempt to locate via exported symbols
      let FuncAddr = DebugSymbol.getFunctionByName(FUNCTION_NAME);

      // If not found, report an error
      if (!FuncAddr) {
          sendEvent(ERROR, {
              error_type: FUNCTION_NOT_FOUND,
              message: `Unable to locate ${ORIGIN_FUNCTION_NAME} function`
          });
          return null;
      }

      // Report function found
      funcFound = true;
      sendEvent(FUNCTION_FOUND, {
          address: FuncAddr.toString(),
          message: `Located ${ORIGIN_FUNCTION_NAME} function`
      });

      return FuncAddr;
  }

  // Initialize the hook and execute immediately
  function initHook() {
      sendEvent(SCRIPT_INITIALIZED, {
          message: `${APP_NAME} ${FUNCTION_BEHAVIOR} monitoring script started`
      });

      // Locate the target function
      const funcAddr = getFunction();
      if (!funcAddr) {
          return;
      }

      // Install the hook for the target function
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
    # Locate the cone and spherical cutout
    cone = None
    sphere_cut = None
    processed_objects = set()
    # Check all objects to find the cone and spherical cutout
    for subobj in doc.Objects:
        if hasattr(subobj, "Shape") and hasattr(subobj.Shape, "ShapeType"):
            # Check if it is an additive cone using TypeId
            if subobj.TypeId == 'PartDesign::AdditiveCone':
                # Use object ID as a unique identifier
                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name

                # Skip if this object has already been processed
                if obj_id in processed_objects:
                    continue
                processed_objects.add(obj_id)

                if subobj.Shape.ShapeType == "Solid":
                    # Check if it is a cone and directly read properties
                    cone_radius1 = subobj.Radius1.Value if hasattr(subobj, "Radius1") else 0
                    cone_radius2 = subobj.Radius2.Value if hasattr(subobj, "Radius2") else 0
                    cone_height = subobj.Height.Value if hasattr(subobj, "Height") else 0

                    # Store cone information
                    cone = {
                        'radius1': cone_radius1,
                        'radius2': cone_radius2,
                        'height': cone_height
                    }

            # Check if it is a subtractive sphere (spherical cutout) using TypeId
            elif subobj.TypeId == 'PartDesign::SubtractiveSphere':
                # Use object ID as a unique identifier
                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name

                # Skip if this object has already been processed
                if obj_id in processed_objects:
                    continue
                processed_objects.add(obj_id)

                if subobj.Shape.ShapeType == "Solid":
                    # Directly retrieve sphere properties
                    sphere_radius = subobj.Radius.Value if hasattr(subobj, "Radius") else 0

                    # Retrieve sphere position
                    sphere_position_x = 0.0
                    sphere_position_y = 0.0
                    sphere_position_z = 0.0

                    if hasattr(subobj, "Placement") and hasattr(subobj.Placement, "Base"):
                        sphere_position_x = subobj.Placement.Base.x
                        sphere_position_y = subobj.Placement.Base.y
                        sphere_position_z = subobj.Placement.Base.z

                    # Store spherical cutout information
                    sphere_cut = {
                        'radius': sphere_radius,
                        'position_x': sphere_position_x,
                        'position_y': sphere_position_y,
                        'position_z': sphere_position_z
                    }

    # Return the result - ensure pure numeric values without units
    # Handle values that may include units
    def extract_value(val):
        if val is None:
            return None
        try:
            # If the value is a string with units (e.g., "10.0 mm"), extract the numeric part
            if isinstance(val, str) and ' ' in val:
                return float(val.split()[0])
            # If the value is a FreeCAD Quantity object, attempt to convert to float
            return float(val)
        except:
            # If conversion fails, return the original value
            return val

    result = {
        'cone_radius1': extract_value(cone['radius1']) if cone else None,
        'cone_radius2': extract_value(cone['radius2']) if cone else None,
        'cone_height': extract_value(cone['height']) if cone else None,
        'sphere_radius': extract_value(sphere_cut['radius']) if sphere_cut else None,
        'sphere_position_x': extract_value(sphere_cut['position_x']) if sphere_cut else None,
        'sphere_position_y': extract_value(sphere_cut['position_y']) if sphere_cut else None,
        'sphere_position_z': extract_value(sphere_cut['position_z']) if sphere_cut else None,
        'has_sphere_cut': sphere_cut is not None
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
