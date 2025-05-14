// FreeCAD Disk with Threaded Hole Monitoring Hook Script
// Used to monitor FreeCAD operations for creating a disk with threaded hole and detect task completion
// After creating a disk with threaded hole and saving the file, the test program detects the save and checks if the document contains a disk with threaded hole that meets requirements

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
from FreeCAD import Vector

# Open the specified file
file_path = '${this.filename}'
doc = FreeCAD.open(file_path)

# Get active document
if doc is None:
    result = None
else:
    # Initialize result parameters
    disk_radius = 0.0
    disk_height = 0.0
    hole_radius = 0.0
    has_thread = False
    is_centered = False
    
    # Initialize threaded hole parameters
    thread_size = ''
    thread_depth = 0.0
    model_thread = False
    
    # Find disk and threaded hole
    cylinder_found = False
    hole_found = False
    disk_center = Vector(0, 0, 0)
    
    # 检查所有对象，寻找圆盘和螺纹孔
    for obj in doc.Objects:
        # 检查是否为实体对象
        if hasattr(obj, "Shape"):
            # 检查形状类型
            if hasattr(obj.Shape, "ShapeType"):
                # Part设计方式创建的对象
                if obj.TypeId == "PartDesign::Body":
                    for subobj in obj.OutList:
                        if hasattr(subobj, "Shape") and hasattr(subobj.Shape, "ShapeType"):
                            # Check cylinder/disk
                            if subobj.TypeId == 'PartDesign::AdditiveCylinder' or subobj.TypeId == 'Part::Cylinder':
                                if not cylinder_found:  # Only process the first disk found
                                    cylinder_found = True
                                    if hasattr(subobj, "Radius"):
                                        disk_radius = subobj.Radius.Value
                                    elif hasattr(subobj.Shape, "Radius"):
                                        disk_radius = subobj.Shape.Radius
                                    
                                    if hasattr(subobj, "Height"):
                                        disk_height = subobj.Height.Value
                                    elif hasattr(subobj.Shape, "Height"):
                                        disk_height = subobj.Shape.Height
                                    
                                    # Record disk center position
                                    if hasattr(subobj, "Placement"):
                                        disk_center = subobj.Placement.Base
                            
                            # Check threaded hole
                            if 'Hole' in subobj.TypeId or 'Thread' in subobj.TypeId:
                                hole_found = True
                                has_thread = True
                                
                                # Only get key parameters that need to be verified
                                
                                # Thread Size
                                if hasattr(subobj, "ThreadSize") or hasattr(subobj, "Size"):
                                    size = getattr(subobj, "ThreadSize", None) or getattr(subobj, "Size", None)
                                    if size:
                                        if isinstance(size, str):
                                            thread_size = size
                                        else:
                                            # If it's a dimension object, try to get the value and convert to string
                                            try:
                                                thread_size = 'M' + str(int(size.Value))
                                            except:
                                                # If parsing fails, keep empty
                                                pass
                                
                                # Get hole radius (to check if centered)
                                if hasattr(subobj, "Diameter"):
                                    hole_radius = subobj.Diameter.Value / 2.0
                                elif hasattr(subobj, "ThreadSize") and not isinstance(subobj.ThreadSize, str):
                                    hole_radius = subobj.ThreadSize.Value / 2.0
                                elif hasattr(subobj, "Radius"):
                                    hole_radius = subobj.Radius.Value
                                
                                # Depth
                                if hasattr(subobj, "Depth"):
                                    thread_depth = subobj.Depth.Value
                                
                                # Model thread
                                if hasattr(subobj, "ModelThread"):
                                    model_thread = bool(subobj.ModelThread)
                                
                                # Check if there are thread features
                                has_thread = ('Threaded' in subobj.TypeId or 
                                             (hasattr(subobj, "Threaded") and subobj.Threaded) or
                                             model_thread)
                                
                                # Check if the hole is in the center of the disk
                                if hasattr(subobj, "Placement"):
                                    hole_center = subobj.Placement.Base
                                    # Calculate distance between hole center and disk center
                                    distance = math.sqrt((hole_center.x - disk_center.x)**2 + 
                                                         (hole_center.y - disk_center.y)**2)
                                    # If distance is less than 10% of hole radius, consider it centered
                                    is_centered = distance < hole_radius * 0.1
                
                # Objects created directly using the Part module
                elif obj.TypeId == 'Part::Cylinder':
                    if not cylinder_found:  # Only process the first disk found
                        cylinder_found = True
                        if hasattr(obj, "Radius"):
                            disk_radius = obj.Radius.Value
                        elif hasattr(obj.Shape, "Radius"):
                            disk_radius = obj.Shape.Radius
                        
                        if hasattr(obj, "Height"):
                            disk_height = obj.Height.Value
                        elif hasattr(obj.Shape, "Height"):
                            disk_height = obj.Shape.Height
                        
                        # Record disk center position
                        if hasattr(obj, "Placement"):
                            disk_center = obj.Placement.Base
    
    # If no explicit thread features are found, try to detect through geometric analysis
    if not has_thread and hole_found:
        for obj in doc.Objects:
            if hasattr(obj, "Shape") and hasattr(obj.Shape, "Edges"):
                # Check for helical edges, which might indicate threads
                for edge in obj.Shape.Edges:
                    if hasattr(edge, "Curve") and hasattr(edge.Curve, "isHelical") and edge.Curve.isHelical():
                        has_thread = True
                        # Try to get pitch from helix
                        if hasattr(edge.Curve, "Pitch"):
                            thread_pitch = edge.Curve.Pitch
                        break
    
    # Return result
    def extract_value(val):
        if val is None:
            return None
        try:
            if isinstance(val, str) and ' ' in val:
                return float(val.split()[0])
            return float(val)
        except:
            return val
    
    result = {
        'disk_radius': extract_value(disk_radius),
        'disk_height': extract_value(disk_height),
        'thread_size': thread_size,
        'thread_depth': extract_value(thread_depth),
        'model_thread': model_thread,
        'has_thread': has_thread,
        'is_centered': is_centered
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
