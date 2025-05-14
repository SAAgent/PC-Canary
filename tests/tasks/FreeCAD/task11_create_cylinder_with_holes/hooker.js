// FreeCAD Cylinder with Holes Monitoring Hook Script
// Used to monitor FreeCAD's cylinder with holes creation operation and detect task completion
// After creating a cylinder with holes and saving the file, the test program listens for the save and checks if there is a cylinder with holes meeting the requirements in the corresponding document

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
    # Find cylinder and holes in the document
    main_cylinder = None
    holes = []
    
    # Check all objects, look for cylinder and holes
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
                            # Use TypeId to check if it's an additive cylinder
                            if subobj.TypeId == 'PartDesign::AdditiveCylinder':
                                # Use object ID as unique identifier
                                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
                                
                                # Skip if this object has been processed
                                if obj_id in processed_objects:
                                    continue
                                processed_objects.add(obj_id)
                                
                                if subobj.Shape.ShapeType == "Solid" and hasattr(subobj.Shape, "Volume"):
                                    # Check if it's a cylinder, read properties directly
                                    cylinder_radius = subobj.Radius.Value if hasattr(subobj, "Radius") else 0
                                    cylinder_height = subobj.Height.Value if hasattr(subobj, "Height") else 0
                                    
                                    # Get position information
                                    cylinder_position = None
                                    if hasattr(subobj, "Placement") and hasattr(subobj.Placement, "Base"):
                                        cylinder_position = {
                                            'x': subobj.Placement.Base.x,
                                            'y': subobj.Placement.Base.y,
                                            'z': subobj.Placement.Base.z
                                        }
                                    
                                    # If no direct properties, try calculating from shape
                                    if cylinder_radius == 0 or cylinder_height == 0:
                                        if len(subobj.Shape.Faces) == 3:  # Cylinder typically has three faces (two bases and one side)
                                            # Check for circular faces
                                            circular_faces = []
                                            cylindrical_face = None
                                            
                                            for face in subobj.Shape.Faces:
                                                if face.Surface.TypeId == 'Part::GeomCylinder':
                                                    cylindrical_face = face
                                                elif face.Surface.TypeId == 'Part::GeomPlane':
                                                    # Check if edges form a circle
                                                    if len(face.Edges) == 1 and face.Edges[0].Curve.TypeId == 'Part::GeomCircle':
                                                        circular_faces.append(face)
                                            
                                            # If found one cylindrical face and two circular faces, can calculate radius and height
                                            if cylindrical_face and len(circular_faces) == 2:
                                                if cylinder_radius == 0:
                                                    cylinder_radius = circular_faces[0].Edges[0].Curve.Radius.Value if hasattr(circular_faces[0].Edges[0].Curve.Radius, "Value") else circular_faces[0].Edges[0].Curve.Radius
                                                
                                                if cylinder_height == 0:
                                                    center1 = circular_faces[0].Surface.Position
                                                    center2 = circular_faces[1].Surface.Position
                                                    cylinder_height = math.sqrt(
                                                        (center1.x - center2.x)**2 + 
                                                        (center1.y - center2.y)**2 + 
                                                        (center1.z - center2.z)**2
                                                    )
                                    
                                    # Store cylinder information
                                    main_cylinder = {
                                        'radius': cylinder_radius,
                                        'height': cylinder_height,
                                        'position': cylinder_position
                                    }
                            
                            # Use TypeId to check if it's a subtractive cylinder (hole)
                            elif subobj.TypeId == 'PartDesign::SubtractiveCylinder':
                                # Use object ID as unique identifier
                                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
                                
                                # Skip if this object has been processed
                                if obj_id in processed_objects:
                                    continue
                                processed_objects.add(obj_id)
                                
                                if subobj.Shape.ShapeType == "Solid" and hasattr(subobj.Shape, "Volume"):
                                    # Get radius directly from object
                                    hole_radius = subobj.Radius.Value if hasattr(subobj, "Radius") else 0
                                    
                                    # Get position information
                                    position = None
                                    if hasattr(subobj, "Placement") and hasattr(subobj.Placement, "Base"):
                                        position = {
                                            'x': subobj.Placement.Base.x,
                                            'y': subobj.Placement.Base.y,
                                            'z': subobj.Placement.Base.z
                                        }
                                    
                                    # Record all subtractive cylinders as holes, no need to check visibility
                                    holes.append({
                                        'radius': hole_radius,
                                        'position': position
                                    })
    
    # Return result - ensure returning pure numbers instead of values with units
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
    
    # Extract cylinder center axis position
    cylinder_center_x = main_cylinder['position']['x'] if main_cylinder and main_cylinder['position'] else 0
    cylinder_center_y = main_cylinder['position']['y'] if main_cylinder and main_cylinder['position'] else 0
    
    # Prepare hole position information
    hole_positions = []
    for hole in holes:
        if hole['position']:
            hole_positions.append({
                'x': hole['position']['x'],
                'y': hole['position']['y'],
                'z': hole['position']['z']
            })
    
    # Sort hole positions - by Z coordinate
    sorted_hole_positions = sorted(hole_positions, key=lambda p: p['z']) if hole_positions else []
    
    result = {
        'cylinder_radius': extract_value(main_cylinder['radius']) if main_cylinder else None,
        'cylinder_height': extract_value(main_cylinder['height']) if main_cylinder else None,
        'hole_radius': extract_value(holes[0]['radius']) if holes else None,
        'hole_count': len(holes),
        'cylinder_position': main_cylinder['position'] if main_cylinder else None,
        'hole_positions': sorted_hole_positions
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