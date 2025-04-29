// FreeCAD创建带螺纹孔圆盘监控钩子脚本
// 用于监听FreeCAD的创建带螺纹孔圆盘操作并检测任务完成情况
// 创建带螺纹孔圆盘后保存文件，测试程序监听到保存后查询对应文档中是否存在符合要求的带螺纹孔圆盘

(function() {
  // 脚本常量设置
  const FUNCTION_NAME = "_ZNK3App8Document10saveToFileEPKc"
  const ORIGIN_FUNCTION_NAME = "Document::saveToFile"
  const FUNCTION_BEHAVIOR = "保存文档"

  const SCRIPT_INITIALIZED = "script_initialized"
  const FUNCTION_NOT_FOUND = "function_not_found"
  const FUNCTION_FOUND = "function_found"
  const FUNCTION_CALLED = "function_called"
  const FUNCTION_KEY_WORD_DETECTED = "function_key_word_detected"
  const ERROR = "error"
  const HOOK_INSTALLED = "hook_installed"

  const APP_NAME = "FreeCAD"
  
  // 全局变量
  let funcFound = false;
  
  // 向评估系统发送事件
  function sendEvent(eventType, data = {}) {
      const payload = {
          event: eventType,
          ...data,
          timestamp: new Date().getTime()
      };
      send(payload);
  }
  
  // 查找Document::saveToFile函数
  function getFunction() {
      // 尝试直接通过导出符号查找
      let FuncAddr = DebugSymbol.getFunctionByName(FUNCTION_NAME);
      
      // 如果没找到，报错
      if (!FuncAddr) {
          sendEvent(ERROR, {
              error_type: FUNCTION_NOT_FOUND,
              message: `无法找到${ORIGIN_FUNCTION_NAME}函数`
          });
          return null;
      }
      
      // 报告找到函数
      funcFound = true;
      sendEvent(FUNCTION_FOUND, {
          address: FuncAddr.toString(),
          message: `找到${ORIGIN_FUNCTION_NAME}函数`
      });
      
      return FuncAddr;
  }
  
  // 初始化钩子并立即执行
  function initHook() {
      sendEvent(SCRIPT_INITIALIZED, {
          message: `${APP_NAME}${FUNCTION_BEHAVIOR}监控脚本已启动`
      });
      
      // 查找搜索函数
      const funcAddr = getFunction();
      if (!funcAddr) {
          return;
      }
      
      // 安装搜索函数钩子
      Interceptor.attach(funcAddr, {
          onEnter: function(args) {
              try {
                  sendEvent(FUNCTION_CALLED, {
                      message: `拦截到${FUNCTION_BEHAVIOR}函数调用`
                  });
                  this.filename = args[1].readCString();
              } catch (error) {
                  sendEvent(ERROR, {
                      error_type: "general_error",
                      message: `执行错误: ${error.message}`
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

# 打开指定的文件
file_path = '${this.filename}'
doc = FreeCAD.open(file_path)

# 获取活动文档
if doc is None:
    result = None
else:
    # 初始化结果参数
    disk_radius = 0.0
    disk_height = 0.0
    hole_radius = 0.0
    has_thread = False
    is_centered = False
    
    # 初始化螺纹孔参数
    thread_size = ''
    thread_depth = 0.0
    model_thread = False
    
    # 查找圆盘和螺纹孔
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
                            # 检查圆柱体/圆盘
                            if subobj.TypeId == 'PartDesign::AdditiveCylinder' or subobj.TypeId == 'Part::Cylinder':
                                if not cylinder_found:  # 只处理第一个找到的圆盘
                                    cylinder_found = True
                                    if hasattr(subobj, "Radius"):
                                        disk_radius = subobj.Radius.Value
                                    elif hasattr(subobj.Shape, "Radius"):
                                        disk_radius = subobj.Shape.Radius
                                    
                                    if hasattr(subobj, "Height"):
                                        disk_height = subobj.Height.Value
                                    elif hasattr(subobj.Shape, "Height"):
                                        disk_height = subobj.Shape.Height
                                    
                                    # 记录圆盘中心位置
                                    if hasattr(subobj, "Placement"):
                                        disk_center = subobj.Placement.Base
                            
                            # 检查螺纹孔
                            if 'Hole' in subobj.TypeId or 'Thread' in subobj.TypeId:
                                hole_found = True
                                has_thread = True
                                
                                # 只获取需要验证的关键参数
                                
                                # 螺纹Size
                                if hasattr(subobj, "ThreadSize") or hasattr(subobj, "Size"):
                                    size = getattr(subobj, "ThreadSize", None) or getattr(subobj, "Size", None)
                                    if size:
                                        if isinstance(size, str):
                                            thread_size = size
                                        else:
                                            # 如果是尺寸对象，尝试获取值并转换为字符串
                                            try:
                                                thread_size = 'M' + str(int(size.Value))
                                            except:
                                                # 如果无法解析，保持为空
                                                pass
                                
                                # 获取孔半径（用于检查是否居中）
                                if hasattr(subobj, "Diameter"):
                                    hole_radius = subobj.Diameter.Value / 2.0
                                elif hasattr(subobj, "ThreadSize") and not isinstance(subobj.ThreadSize, str):
                                    hole_radius = subobj.ThreadSize.Value / 2.0
                                elif hasattr(subobj, "Radius"):
                                    hole_radius = subobj.Radius.Value
                                
                                # 深度
                                if hasattr(subobj, "Depth"):
                                    thread_depth = subobj.Depth.Value
                                
                                # 模型螺纹
                                if hasattr(subobj, "ModelThread"):
                                    model_thread = bool(subobj.ModelThread)
                                
                                # 检查是否有螺纹特征
                                has_thread = ('Threaded' in subobj.TypeId or 
                                             (hasattr(subobj, "Threaded") and subobj.Threaded) or
                                             model_thread)
                                
                                # 检查孔是否在圆盘中心
                                if hasattr(subobj, "Placement"):
                                    hole_center = subobj.Placement.Base
                                    # 计算孔中心与圆盘中心的距离
                                    distance = math.sqrt((hole_center.x - disk_center.x)**2 + 
                                                         (hole_center.y - disk_center.y)**2)
                                    # 如果距离小于孔半径的10%，认为是居中的
                                    is_centered = distance < hole_radius * 0.1
                
                # 直接使用Part模块创建的对象
                elif obj.TypeId == 'Part::Cylinder':
                    if not cylinder_found:  # 只处理第一个找到的圆盘
                        cylinder_found = True
                        if hasattr(obj, "Radius"):
                            disk_radius = obj.Radius.Value
                        elif hasattr(obj.Shape, "Radius"):
                            disk_radius = obj.Shape.Radius
                        
                        if hasattr(obj, "Height"):
                            disk_height = obj.Height.Value
                        elif hasattr(obj.Shape, "Height"):
                            disk_height = obj.Shape.Height
                        
                        # 记录圆盘中心位置
                        if hasattr(obj, "Placement"):
                            disk_center = obj.Placement.Base
    
    # 如果没有找到明确的螺纹特征，尝试通过几何分析检测
    if not has_thread and hole_found:
        for obj in doc.Objects:
            if hasattr(obj, "Shape") and hasattr(obj.Shape, "Edges"):
                # 检查是否有螺旋边缘，这可能表示螺纹
                for edge in obj.Shape.Edges:
                    if hasattr(edge, "Curve") and hasattr(edge.Curve, "isHelical") and edge.Curve.isHelical():
                        has_thread = True
                        # 尝试从螺旋线获取螺距
                        if hasattr(edge.Curve, "Pitch"):
                            thread_pitch = edge.Curve.Pitch
                        break
    
    # 返回结果
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
                        message: `检测到${FUNCTION_BEHAVIOR}操作`,
                        filename: this.filename,
                        code: pythonCode
                    });
                }
                // 检测关键字
              } catch (error) {
                  sendEvent(ERROR, {
                      error_type: "general_error",
                      message: `执行错误: ${error.message}`
                  });
              }
          }
      });
      
      sendEvent(HOOK_INSTALLED, {
          message: `钩子安装完成，等待${FUNCTION_BEHAVIOR}操作...`
      });
  }
  
  // 立即执行钩子初始化
  initHook();
})();
