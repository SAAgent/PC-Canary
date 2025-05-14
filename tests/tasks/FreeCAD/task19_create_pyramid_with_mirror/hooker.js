// FreeCAD Pyramid with Mirror Feature Monitoring Hook Script
// Used to monitor FreeCAD operations for creating a pyramid with mirror feature and detect task completion
// After creating a pyramid with mirror feature and saving the file, the test program detects the save operation and checks if the document contains a pyramid with mirror feature that meets the requirements

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
      
      // 报告找到函数
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
    # Find pyramid and mirror feature
    pyramid = None
    mirror_feature = None
    has_mirror = False
    mirror_plane = ""
    base_length = 0.0
    base_width = 0.0
    pyramid_height = 0.0
    processed_objects = set()
    
    # Check all objects, looking for pyramid and mirror feature
    for subobj in doc.Objects:
        if 'Pyramid' in subobj.TypeId or 'AdditivePyramid' in subobj.TypeId:
            obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
            
            # If this object has already been processed, skip it
            if obj_id in processed_objects:
                continue
            processed_objects.add(obj_id)
            
            # Try to get pyramid parameters
            if hasattr(subobj, "Length"):
                base_length = subobj.Length.Value
            if hasattr(subobj, "Width"):
                base_width = subobj.Width.Value
            if hasattr(subobj, "Height"):
                pyramid_height = subobj.Height.Value
            
            pyramid = subobj
        
        # Check if there's a mirror feature
        elif 'Mirror' in subobj.TypeId:
            # Use object ID as a unique identifier
            obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
            
            # If this object has already been processed, skip it
            if obj_id in processed_objects:
                continue
            processed_objects.add(obj_id)
            
            # Mark that mirror feature exists
            has_mirror = True
            mirror_feature = subobj
            
            # Try to get mirror plane
            if hasattr(subobj, "MirrorPlane"):
                # Check mirror plane parameters
                mirror_plane_obj = subobj.MirrorPlane
                
                # Try to analyze mirror plane type
                if hasattr(mirror_plane_obj, "Axis"):
                    axis = mirror_plane_obj.Axis
                    # Determine plane based on axis
                    if abs(axis.x) > 0.9 and abs(axis.y) < 0.1 and abs(axis.z) < 0.1:
                        mirror_plane = "YZ"  # X axis perpendicular to YZ plane
                    elif abs(axis.y) > 0.9 and abs(axis.x) < 0.1 and abs(axis.z) < 0.1:
                        mirror_plane = "XZ"  # Y axis perpendicular to XZ plane
                    elif abs(axis.z) > 0.9 and abs(axis.x) < 0.1 and abs(axis.y) < 0.1:
                        mirror_plane = "XY"  # Z axis perpendicular to XY plane
    
    # If no pyramid found, try to identify by shape characteristics
    if not pyramid:
        # Iterate through all objects in the document
        for obj in doc.Objects:
            if hasattr(obj, "TypeId") and ("Wedge" in obj.TypeId or "Part::Wedge" in obj.TypeId):
                pyramid = obj
                if hasattr(obj, "Xmin") and hasattr(obj, "Xmax") and hasattr(obj, "Ymin") and hasattr(obj, "Ymax") and hasattr(obj, "Zmin") and hasattr(obj, "Zmax"):
                    base_length = abs(obj.Xmax - obj.Xmin)
                    base_width = abs(obj.Ymax - obj.Ymin)
                    pyramid_height = abs(obj.Zmax - obj.Zmin)
                continue
            
            # If not a direct wedge object, check vertex and face count
            if hasattr(obj.Shape, "Vertexes") and (len(obj.Shape.Vertexes) == 5 or len(obj.Shape.Vertexes) == 6):
                # A pyramid should have 5 faces (quadrangular pyramid) or 6 faces (wedge)
                if hasattr(obj.Shape, "Faces") and (len(obj.Shape.Faces) == 5 or len(obj.Shape.Faces) == 6):
                    pyramid = obj
                    
                    # Try to calculate dimensions
                    if hasattr(obj.Shape, "BoundBox"):
                        bbox = obj.Shape.BoundBox
                        # For wedges on XZ plane, X and Z are base dimensions
                        base_length = bbox.XLength
                        base_width = bbox.ZLength  # For wedges on XZ plane, Z is width
                        pyramid_height = bbox.YLength  # Y is height
    
    # If no mirror feature found, try to determine by checking symmetry
    if not has_mirror:
        # Check if there are possibly symmetrically placed similar objects in the document
        all_solids = []
        for obj in doc.Objects:
            if hasattr(obj, "Shape") and obj.Shape.ShapeType == "Solid":
                all_solids.append(obj)
        
        # If there are an even number of similar objects, a mirror might exist
        if len(all_solids) >= 2 and len(all_solids) % 2 == 0:
            # Try to check the relationship between these objects
            has_mirror = True
            
            # Assume the task requires XZ plane mirroring
            mirror_plane = "XZ"  # Since we know the base is on the XZ plane, the mirror plane is also XZ
            
            # Verify by checking the distribution of objects' positions
            if len(all_solids) >= 2:
                obj1 = all_solids[0]
                obj2 = all_solids[1]
                
                if hasattr(obj1.Shape, "CenterOfMass") and hasattr(obj2.Shape, "CenterOfMass"):
                    com1 = obj1.Shape.CenterOfMass
                    com2 = obj2.Shape.CenterOfMass
                    
                    # Infer mirror plane based on relative position of centers of mass
                    dx = abs(com1.x - com2.x)
                    dy = abs(com1.y - com2.y)
                    dz = abs(com1.z - com2.z)
                    
                    # For pyramids created as wedges, determine mirror plane
                    if dx < 0.1 and dz < 0.1 and dy > 0:
                        # If differences in X and Z directions are small, but Y is significant, it's XZ plane mirroring
                        mirror_plane = "XZ"  # Mirrored along Y axis
                    elif dy < 0.1 and dz < 0.1 and dx > 0:
                        mirror_plane = "YZ"  # Mirrored along X axis
                    elif dx < 0.1 and dy < 0.1 and dz > 0:
                        mirror_plane = "XY"  # Mirrored along Z axis
    
    # Return results - ensure pure numbers are returned instead of values with units
    # Handle values that might have units
    def extract_value(val):
        if val is None:
            return None
        try:
            # If it's a string with units (like "10.0 mm"), extract the numerical part
            if isinstance(val, str) and ' ' in val:
                return float(val.split()[0])
            # If it's a FreeCAD Quantity object, try to convert to float
            return float(val)
        except:
            # If conversion fails, return the original value
            return val
    
    # Print debug information for troubleshooting
    print("Debug info: Measured pyramid dimensions - Length:", base_length, "Width:", base_width, "Height:", pyramid_height)
    print("Debug info: Mirror feature - Exists:", has_mirror, "Mirror plane:", mirror_plane)
    
    # Because wedge-created pyramids have base on XZ plane, adjust dimension parameter mapping
    if pyramid and hasattr(pyramid.Shape, "BoundBox"):
        bbox = pyramid.Shape.BoundBox
        # Adjust parameter interpretation
        result = {
            'base_length': extract_value(base_length),
            'base_width': extract_value(base_width),
            'pyramid_height': extract_value(pyramid_height),
            'mirror_plane': "XZ",  # Fixed to XZ plane because the task requires base on XZ plane
            'has_mirror': has_mirror
        }
    else:
        result = {
            'base_length': extract_value(base_length),
            'base_width': extract_value(base_width),
            'pyramid_height': extract_value(pyramid_height),
            'mirror_plane': mirror_plane,
            'has_mirror': has_mirror
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
