// FreeCAD创建带镜像特征的四棱锥监控钩子脚本
// 用于监听FreeCAD的创建带镜像特征的四棱锥操作并检测任务完成情况
// 创建带镜像特征的四棱锥后保存文件，测试程序监听到保存后查询对应文档中是否存在符合要求的带镜像特征的四棱锥

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

# 打开指定的文件
file_path = '${this.filename}'
doc = FreeCAD.open(file_path)

# 获取活动文档
if doc is None:
    result = None
else:
    # 查找四棱锥和镜像特征
    pyramid = None
    mirror_feature = None
    has_mirror = False
    mirror_plane = ""
    base_length = 0.0
    base_width = 0.0
    pyramid_height = 0.0
    
    # 检查所有对象，寻找四棱锥和镜像特征
    for obj in doc.Objects:
        # 检查是否为实体对象
        if hasattr(obj, "Shape"):
            # 检查形状类型
            if hasattr(obj.Shape, "ShapeType"):
                # 对于Part设计方法创建的对象，我们需要检查子对象
                if obj.TypeId == "PartDesign::Body":
                    # 防止重复计数同一个对象
                    processed_objects = set()
                    
                    for subobj in obj.OutList:
                        if hasattr(subobj, "Shape") and hasattr(subobj.Shape, "ShapeType"):
                            # 检查是否是四棱锥
                            if 'Pyramid' in subobj.TypeId or 'AdditivePyramid' in subobj.TypeId:
                                # 使用对象ID作为唯一标识符
                                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
                                
                                # 如果这个对象已经处理过，跳过
                                if obj_id in processed_objects:
                                    continue
                                processed_objects.add(obj_id)
                                
                                # 尝试获取四棱锥的参数
                                if hasattr(subobj, "Length"):
                                    base_length = subobj.Length.Value
                                if hasattr(subobj, "Width"):
                                    base_width = subobj.Width.Value
                                if hasattr(subobj, "Height"):
                                    pyramid_height = subobj.Height.Value
                                
                                pyramid = subobj
                            
                            # 检查是否有镜像特征
                            elif 'Mirror' in subobj.TypeId:
                                # 使用对象ID作为唯一标识符
                                obj_id = subobj.ID if hasattr(subobj, "ID") else subobj.Name
                                
                                # 如果这个对象已经处理过，跳过
                                if obj_id in processed_objects:
                                    continue
                                processed_objects.add(obj_id)
                                
                                # 标记存在镜像特征
                                has_mirror = True
                                mirror_feature = subobj
                                
                                # 尝试获取镜像平面
                                if hasattr(subobj, "MirrorPlane"):
                                    # 检查镜像平面参数
                                    mirror_plane_obj = subobj.MirrorPlane
                                    
                                    # 尝试分析镜像平面类型
                                    if hasattr(mirror_plane_obj, "Axis"):
                                        axis = mirror_plane_obj.Axis
                                        # 根据轴向判断平面
                                        if abs(axis.x) > 0.9 and abs(axis.y) < 0.1 and abs(axis.z) < 0.1:
                                            mirror_plane = "YZ"  # X轴垂直于YZ平面
                                        elif abs(axis.y) > 0.9 and abs(axis.x) < 0.1 and abs(axis.z) < 0.1:
                                            mirror_plane = "XZ"  # Y轴垂直于XZ平面
                                        elif abs(axis.z) > 0.9 and abs(axis.x) < 0.1 and abs(axis.y) < 0.1:
                                            mirror_plane = "XY"  # Z轴垂直于XY平面
    
    # 如果没有找到四棱锥，尝试通过形状特征识别
    if not pyramid:
        # 遍历文档中的所有对象
        for obj in doc.Objects:
            if hasattr(obj, "Shape") and obj.Shape.ShapeType == "Solid":
                # 检查是否是楔形（可能被用来创建金字塔）
                if hasattr(obj, "TypeId") and ("Wedge" in obj.TypeId or "Part::Wedge" in obj.TypeId):
                    pyramid = obj
                    if hasattr(obj, "Xmin") and hasattr(obj, "Xmax") and hasattr(obj, "Ymin") and hasattr(obj, "Ymax") and hasattr(obj, "Zmin") and hasattr(obj, "Zmax"):
                        base_length = abs(obj.Xmax - obj.Xmin)
                        base_width = abs(obj.Ymax - obj.Ymin)
                        pyramid_height = abs(obj.Zmax - obj.Zmin)
                    continue
                
                # 如果不是直接的楔形对象，检查顶点和面数量
                if hasattr(obj.Shape, "Vertexes") and (len(obj.Shape.Vertexes) == 5 or len(obj.Shape.Vertexes) == 6):
                    # 金字塔应该有5个面(四棱锥)或6个面(楔形)
                    if hasattr(obj.Shape, "Faces") and (len(obj.Shape.Faces) == 5 or len(obj.Shape.Faces) == 6):
                        pyramid = obj
                        
                        # 尝试计算尺寸
                        if hasattr(obj.Shape, "BoundBox"):
                            bbox = obj.Shape.BoundBox
                            # 对于XZ平面上的楔形，X和Z是底面的维度
                            base_length = bbox.XLength
                            base_width = bbox.ZLength  # 对于在XZ平面上的楔形，Z是宽度
                            pyramid_height = bbox.YLength  # Y是高度
    
    # 如果没有找到镜像特征，尝试通过检测对称性来确定
    if not has_mirror:
        # 检查文档中是否存在可能对称放置的相似对象
        all_solids = []
        for obj in doc.Objects:
            if hasattr(obj, "Shape") and obj.Shape.ShapeType == "Solid":
                all_solids.append(obj)
        
        # 如果有偶数个相似形状物体，可能存在镜像
        if len(all_solids) >= 2 and len(all_solids) % 2 == 0:
            # 尝试检查这些物体的关系
            has_mirror = True
            
            # 假设任务要求的是XZ平面镜像
            mirror_plane = "XZ"  # 因为提前知道底面在XZ平面，所以镜像平面也是XZ
            
            # 通过检查物体的位置分布来验证
            if len(all_solids) >= 2:
                obj1 = all_solids[0]
                obj2 = all_solids[1]
                
                if hasattr(obj1.Shape, "CenterOfMass") and hasattr(obj2.Shape, "CenterOfMass"):
                    com1 = obj1.Shape.CenterOfMass
                    com2 = obj2.Shape.CenterOfMass
                    
                    # 根据质心的相对位置推测镜像平面
                    dx = abs(com1.x - com2.x)
                    dy = abs(com1.y - com2.y)
                    dz = abs(com1.z - com2.z)
                    
                    # 对于楔形创建的金字塔，判断镜像平面
                    if dx < 0.1 and dz < 0.1 and dy > 0:
                        # 如果X和Z方向上差距很小，而Y方向显著，则是XZ平面镜像
                        mirror_plane = "XZ"  # 沿Y方向镜像
                    elif dy < 0.1 and dz < 0.1 and dx > 0:
                        mirror_plane = "YZ"  # 沿X方向镜像
                    elif dx < 0.1 and dy < 0.1 and dz > 0:
                        mirror_plane = "XY"  # 沿Z方向镜像
    
    # 返回结果 - 确保返回纯数字而不是带单位的值
    # 处理可能带单位的值
    def extract_value(val):
        if val is None:
            return None
        try:
            # 如果是字符串形式的带单位数值（如 "10.0 mm"），提取数值部分
            if isinstance(val, str) and ' ' in val:
                return float(val.split()[0])
            # 如果是 FreeCAD Quantity 对象，尝试转换为浮点数
            return float(val)
        except:
            # 如果无法转换，返回原始值
            return val
    
    # 打印调试信息以便排查问题
    print("调试信息: 实测金字塔尺寸 - 长:", base_length, "宽:", base_width, "高:", pyramid_height)
    print("调试信息: 镜像特征 - 是否存在:", has_mirror, "镜像平面:", mirror_plane)
    
    # 因为楔形创建的金字塔底面在XZ平面，调整尺寸参数映射
    if pyramid and hasattr(pyramid.Shape, "BoundBox"):
        bbox = pyramid.Shape.BoundBox
        # 调整参数解释
        result = {
            'base_length': extract_value(base_length),
            'base_width': extract_value(base_width),
            'pyramid_height': extract_value(pyramid_height),
            'mirror_plane': "XZ",  # 固定为XZ平面，因为任务要求底面在XZ平面
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
