// FreeCAD Triangular Prism with Stepped Hole Monitoring Hook Script
// Used to monitor FreeCAD operations for creating a triangular prism with stepped hole and detect task completion
// After creating a triangular prism with stepped hole and saving the file, the test program detects the save operation and checks if the document contains a triangular prism with stepped hole that meets the requirements

(function() {
  // Script constants setup
  const FUNCTION_NAME = "_ZNK3App8Document10saveToFileEPKc";
  const ORIGIN_FUNCTION_NAME = "Document::saveToFile";
  const FUNCTION_BEHAVIOR = "Save document";

  const SCRIPT_INITIALIZED = "script_initialized";
  const FUNCTION_NOT_FOUND = "function_not_found";
  const FUNCTION_FOUND = "function_found";
  const FUNCTION_CALLED = "function_called";
  const FUNCTION_KEY_WORD_DETECTED = "function_key_word_detected";
  const ERROR = "error";
  const HOOK_INSTALLED = "hook_installed";

  const APP_NAME = "FreeCAD";

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
      // Try to find directly through export symbols
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
          message: `${APP_NAME} ${FUNCTION_BEHAVIOR} monitoring script started`
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

# Open specified file
file_path = '${this.filename}'
doc = FreeCAD.open(file_path)

# Get active document
if doc is None:
    result = None
else:
    # Find triangular prism and stepped hole
    prism = None
    hole_inner_radius = 0.0
    hole_outer_radius = 0.0
    hole_depth = 0.0
    prism_circumradius = 0.0
    prism_height = 0.0
    inner_hole_through = False
    
    # Store detected cylinders for later analysis
    cylinders = []

    # First check all objects, looking for triangular prism and cylinders
    for obj in doc.Objects:
        # Check if it's a solid object
        if hasattr(obj, "Shape") and obj.Shape.ShapeType == "Solid":
            # Check if it's a triangular prism
            if hasattr(obj, "TypeId"):
                # Directly check if it's a prism object
                if "Prism" in obj.TypeId:
                    prism = obj
                    if hasattr(obj, "Circumradius"):
                        prism_circumradius = obj.Circumradius.Value
                    if hasattr(obj, "Height"):
                        prism_height = obj.Height.Value
                
                # Or check if it's a prism-like object formed by extruding a polygon
                elif "Extrude" in obj.TypeId or "Pad" in obj.TypeId:
                    # For extruded shapes, check the number of vertices and faces
                    if hasattr(obj.Shape, "Vertexes") and hasattr(obj.Shape, "Faces"):
                        # A triangular prism should have 6 vertices and 5 faces (3 quadrilateral sides + 2 triangular bases)
                        if len(obj.Shape.Vertexes) == 6 and (len(obj.Shape.Faces) == 5 or len(obj.Shape.Faces) == 8):
                            prism = obj
                            # Use bounding box to get approximate dimensions
                            if hasattr(obj.Shape, "BoundBox"):
                                bbox = obj.Shape.BoundBox
                                # Estimate circumradius as approximately the radius of the circle around the triangle, about half to two-thirds of the longest side
                                max_dim = max(bbox.XLength, bbox.ZLength)
                                prism_circumradius = max_dim / 2
                                # Height is typically in Y direction
                                prism_height = bbox.YLength
                
                # Check if it's a cylinder (might be a hole)
                elif "Cylinder" in obj.TypeId or "Hole" in obj.TypeId:
                    if hasattr(obj, "Radius") and hasattr(obj, "Height"):
                        radius = obj.Radius.Value
                        height = obj.Height.Value
                        # Store all cylinders for later processing
                        cylinders.append({
                            'radius': radius,
                            'height': height,
                            'obj': obj
                        })
            
            # If the object doesn't have a clear TypeId or is not a standard type, try to determine by shape characteristics
            elif hasattr(obj.Shape, "Vertexes") and hasattr(obj.Shape, "Faces"):
                # Check if it might be a triangular prism (6 vertices, 5 faces)
                if len(obj.Shape.Vertexes) == 6 and len(obj.Shape.Faces) == 5:
                    if prism is None: # If we haven't found a prism yet
                        prism = obj
                        # Use bounding box to get approximate dimensions
                        if hasattr(obj.Shape, "BoundBox"):
                            bbox = obj.Shape.BoundBox
                            # Estimate circumradius as approximately the radius of the circle around the triangle, about half to two-thirds of the longest side
                            max_dim = max(bbox.XLength, bbox.ZLength)
                            prism_circumradius = max_dim / 2
                            # Height is typically in Y direction
                            prism_height = bbox.YLength
    
    # Update logic for determining if the small hole goes through
    if len(cylinders) > 0:
        # Sort by radius, smaller ones might be inner holes, larger ones might be outer holes
        cylinders.sort(key=lambda x: x['radius'])

        if len(cylinders) >= 2:
            inner_cylinder = cylinders[0]
            outer_cylinder = cylinders[1]

            hole_inner_radius = inner_cylinder['radius']
            hole_outer_radius = outer_cylinder['radius']
            hole_depth = outer_cylinder['height']

            # Check if the small hole goes through the triangular prism
            if prism is not None and hasattr(prism.Shape, "BoundBox"):
                prism_bbox = prism.Shape.BoundBox
                inner_cylinder_bbox = inner_cylinder['obj'].Shape.BoundBox

                # Check if the bottom of the small hole touches the bottom of the prism
                bottom_contact = abs(inner_cylinder_bbox.ZMin - prism_bbox.ZMin) < 0.1

                # Check if the top of the small hole is higher than or touches the bottom of the large hole
                top_contact = inner_cylinder_bbox.ZMax >= outer_cylinder['obj'].Shape.BoundBox.ZMin

                inner_hole_through = bottom_contact and top_contact

        elif len(cylinders) == 1:
            cylinder = cylinders[0]
            hole_inner_radius = cylinder['radius']

            if prism is not None and hasattr(prism.Shape, "BoundBox"):
                prism_bbox = prism.Shape.BoundBox
                cylinder_bbox = cylinder['obj'].Shape.BoundBox

                # Check if the bottom of the hole touches the bottom of the prism
                bottom_contact = abs(cylinder_bbox.ZMin - prism_bbox.ZMin) < 0.1

                # Check if the top of the hole is higher than or touches the top of the prism (assuming there's only one hole, it touches the top of the prism)
                top_contact = cylinder_bbox.ZMax >= prism_bbox.ZMax

                inner_hole_through = bottom_contact and top_contact

    result = {
        'prism_circumradius': prism_circumradius,
        'prism_height': prism_height,
        'hole_inner_radius': hole_inner_radius,
        'hole_outer_radius': hole_outer_radius,
        'hole_depth': hole_depth,
        'inner_hole_through': inner_hole_through
    }`;
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
          message: `Hook installation complete, waiting for ${FUNCTION_BEHAVIOR} operation...`
      });
  }

  // Execute hook initialization immediately
  initHook();
})();
