// FreeCAD Octagonal Prism with Central Circular Hole Monitoring Hook Script
// Used to monitor FreeCAD operations for creating an octagonal prism with central circular hole and detect task completion
// After creating an octagonal prism with central circular hole and saving the file, the test program detects the save and checks if the document contains an octagonal prism with central circular hole that meets requirements

(function() {
  // Script constants setup
  const FUNCTION_NAME = "_ZNK3App8Document10saveToFileEPKc"
  const ORIGIN_FUNCTION_NAME = "Document::saveToFile"
  const FUNCTION_BEHAVIOR = "Save document"

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
  
  // Send event to evaluation system
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
      // Try to find directly through exported symbol
      let FuncAddr = DebugSymbol.getFunctionByName(FUNCTION_NAME);
      
      // If not found, report error
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
    # Find octagonal prism and center hole
    prism = None
    hole = None
    has_hole = False
    hole_radius = 0.0
    sides_count = 0
    processed_objects = set()
    
    # Check all objects, looking for prism and hole
    for subobj in doc.Objects:
        if hasattr(subobj, "Shape") and hasattr(subobj.Shape, "ShapeType"):
            # Look for polygonal prism
            if ('Prism' in subobj.TypeId or 'Extrusion' in subobj.TypeId 
                or 'Pad' in subobj.TypeId or 'AdditivePrism' in subobj.TypeId):
                # Use object ID as a unique identifier
                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
                
                # If this object has been processed, skip
                if obj_id in processed_objects:
                    continue
                processed_objects.add(obj_id)
                
                if subobj.Shape.ShapeType == "Solid":
                    # Try to get prism parameters
                    if hasattr(subobj, "Polygon"):
                        # If it's a polygon prism, get number of sides
                        sides_count = subobj.Polygon
                    elif hasattr(subobj, "Circumradius"):
                        # Get circumscribed radius
                        prism_radius = subobj.Circumradius.Value
                    elif hasattr(subobj, "Height"):
                        # Get height
                        prism_height = subobj.Height.Value
                    elif hasattr(subobj, "Length"):
                        # In some cases, length may represent height
                        prism_height = subobj.Length.Value
                    
                    # If parameters are incomplete, analyze shape
                    if sides_count == 0:
                        # Try to identify number of sides from shape
                        if hasattr(subobj.Shape, "Faces"):
                            # For a prism, there should be sides+2 faces (bottom, top, and side faces)
                            face_count = len(subobj.Shape.Faces)
                            if face_count >= 3:  # At least three faces
                                # Number of side faces may represent polygon sides
                                possible_sides = face_count - 2
                                if possible_sides >= 3:  # At least a triangle
                                    sides_count = possible_sides
            
            # Check if there is a center hole
            elif ('Pocket' in subobj.TypeId or 'SubtractiveCylinder' in subobj.TypeId 
                    or 'Cut' in subobj.TypeId or 'Hole' in subobj.TypeId):
                # Use object ID as a unique identifier
                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
                
                # If this object has been processed, skip
                if obj_id in processed_objects:
                    continue
                processed_objects.add(obj_id)
                
                # Mark that a hole exists
                has_hole = True
                
                # Try to get hole radius
                if hasattr(subobj, "Radius"):
                    hole_radius = subobj.Radius.Value
                elif hasattr(subobj, "Diameter"):
                    hole_radius = subobj.Diameter.Value / 2
    
    # If complete information cannot be obtained through attributes, try geometric analysis
    # Calculate the circumscribed circle radius and height of the prism
    if not prism:
        prism_radius = 0.0
        prism_height = 0.0
        
        # Traverse all objects in the document
        for obj in doc.Objects:
            if hasattr(obj, "Shape") and hasattr(obj.Shape, "BoundBox"):
                # Get bounding box
                bbox = obj.Shape.BoundBox
                
                # Calculate circumscribed circle radius in X-Y plane
                center_x = (bbox.XMin + bbox.XMax) / 2
                center_y = (bbox.YMin + bbox.YMax) / 2
                
                # Find the farthest vertex as the circumscribed circle radius
                max_radius = 0.0
                
                if hasattr(obj.Shape, "Vertexes"):
                    for vertex in obj.Shape.Vertexes:
                        dx = vertex.X - center_x
                        dy = vertex.Y - center_y
                        distance = math.sqrt(dx*dx + dy*dy)
                        max_radius = max(max_radius, distance)
                
                if max_radius > 0:
                    prism_radius = max_radius
                
                # Height is typically the dimension in the Z direction
                prism_height = bbox.ZMax - bbox.ZMin
                
                # Verify if it could be an octagonal prism
                if hasattr(obj.Shape, "Faces") and sides_count == 0:
                    # Count the number of faces
                    face_count = len(obj.Shape.Faces)
                    # A prism should have sides+2 faces
                    if face_count >= 5:  # At least a triangular prism (5 faces)
                        sides_count = face_count - 2
    
    # Verify center hole - check if hole is close to center
    if not has_hole:
        # Try to detect center hole geometrically
        for obj in doc.Objects:
            if hasattr(obj, "Shape") and hasattr(obj.Shape, "Faces"):
                # Look for cylindrical inner surface, which might be a hole
                for face in obj.Shape.Faces:
                    if hasattr(face, "Surface") and hasattr(face.Surface, "Radius"):
                        # Found a cylindrical surface
                        potential_hole_radius = face.Surface.Radius
                        
                        # Check if this face is near the center of the object
                        if hasattr(face, "CenterOfMass"):
                            center_of_mass = face.CenterOfMass
                            # Check if the center of the face is close to the object center (XY plane)
                            if abs(center_of_mass.x) < 1.0 and abs(center_of_mass.y) < 1.0:
                                has_hole = True
                                hole_radius = potential_hole_radius
                                sides_count -= 1
                                break
    
    # Return result - ensure pure numbers are returned rather than values with units
    # Handle values that may have units
    def extract_value(val):
        if val is None:
            return None
        try:
            # If it's a string form of a value with units (e.g. "10.0 mm"), extract the numeric part
            if isinstance(val, str) and ' ' in val:
                return float(val.split()[0])
            # If it's a FreeCAD Quantity object, try to convert to float
            return float(val)
        except:
            # If conversion fails, return the original value
            return val
    
    result = {
        'prism_radius': extract_value(prism_radius),
        'prism_height': extract_value(prism_height),
        'hole_radius': extract_value(hole_radius),
        'sides_count': sides_count,
        'has_hole': has_hole
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
          message: `Hook installation completed, waiting for ${FUNCTION_BEHAVIOR} operation...`
      });
  }
  
  // Execute hook initialization immediately
  initHook();
})();
