// FreeCAD创建带阶梯孔的三棱柱监控钩子脚本
// 用于监听FreeCAD的创建带阶梯孔的三棱柱操作并检测任务完成情况
// 创建带阶梯孔的三棱柱后保存文件，测试程序监听到保存后查询对应文档中是否存在符合要求的带阶梯孔的三棱柱

(function() {
  // 脚本常量设置
  const FUNCTION_NAME = "_ZNK3App8Document10saveToFileEPKc";
  const ORIGIN_FUNCTION_NAME = "Document::saveToFile";
  const FUNCTION_BEHAVIOR = "保存文档";

  const SCRIPT_INITIALIZED = "script_initialized";
  const FUNCTION_NOT_FOUND = "function_not_found";
  const FUNCTION_FOUND = "function_found";
  const FUNCTION_CALLED = "function_called";
  const FUNCTION_KEY_WORD_DETECTED = "function_key_word_detected";
  const ERROR = "error";
  const HOOK_INSTALLED = "hook_installed";

  const APP_NAME = "FreeCAD";

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
    # 查找三棱柱和阶梯孔
    prism = None
    hole_inner_radius = 0.0
    hole_outer_radius = 0.0
    hole_depth = 0.0
    prism_circumradius = 0.0
    prism_height = 0.0
    inner_hole_through = False
    
    # 用于存储检测到的圆柱体，便于后续分析
    cylinders = []

    # 首先检查所有对象，寻找三棱柱和圆柱体
    for obj in doc.Objects:
        # 检查是否为实体对象
        if hasattr(obj, "Shape") and obj.Shape.ShapeType == "Solid":
            # 检查是否为三棱柱
            if hasattr(obj, "TypeId"):
                # 直接检查是否是三棱柱对象
                if "Prism" in obj.TypeId:
                    prism = obj
                    if hasattr(obj, "Circumradius"):
                        prism_circumradius = obj.Circumradius.Value
                    if hasattr(obj, "Height"):
                        prism_height = obj.Height.Value
                
                # 或者检查是否是通过多边形挤出形成的类棱柱体
                elif "Extrude" in obj.TypeId or "Pad" in obj.TypeId:
                    # 对于挤出的形状，检查顶点数量和面的数量
                    if hasattr(obj.Shape, "Vertexes") and hasattr(obj.Shape, "Faces"):
                        # 三棱柱应该有6个顶点和5个面（3个四边形侧面+2个三角形底面）
                        if len(obj.Shape.Vertexes) == 6 and (len(obj.Shape.Faces) == 5 or len(obj.Shape.Faces) == 8):
                            prism = obj
                            # 使用边界框获取近似尺寸
                            if hasattr(obj.Shape, "BoundBox"):
                                bbox = obj.Shape.BoundBox
                                # 估计外接圆半径约为围绕三角形的圆的半径，大约是最长边的一半到三分之二
                                max_dim = max(bbox.XLength, bbox.ZLength)
                                prism_circumradius = max_dim / 2
                                # 高度通常是Y方向
                                prism_height = bbox.YLength
                
                # 检查是否为圆柱体（可能是孔）
                elif "Cylinder" in obj.TypeId or "Hole" in obj.TypeId:
                    if hasattr(obj, "Radius") and hasattr(obj, "Height"):
                        radius = obj.Radius.Value
                        height = obj.Height.Value
                        # 存储所有圆柱体以便后续处理
                        cylinders.append({
                            'radius': radius,
                            'height': height,
                            'obj': obj
                        })
            
            # 如果对象没有明确的TypeId或不是标准类型，尝试通过形状特征判断
            elif hasattr(obj.Shape, "Vertexes") and hasattr(obj.Shape, "Faces"):
                # 检查是否可能是三棱柱（6个顶点，5个面）
                if len(obj.Shape.Vertexes) == 6 and len(obj.Shape.Faces) == 5:
                    if prism is None: # 如果还没找到三棱柱
                        prism = obj
                        # 使用边界框获取近似尺寸
                        if hasattr(obj.Shape, "BoundBox"):
                            bbox = obj.Shape.BoundBox
                            # 估计外接圆半径约为围绕三角形的圆的半径，大约是最长边的一半到三分之二
                            max_dim = max(bbox.XLength, bbox.ZLength)
                            prism_circumradius = max_dim / 2
                            # 高度通常是Y方向
                            prism_height = bbox.YLength
    
    # 更新小孔是否贯穿的判断逻辑
    if len(cylinders) > 0:
        # 按半径排序，小的可能是内孔，大的可能是外孔
        cylinders.sort(key=lambda x: x['radius'])

        if len(cylinders) >= 2:
            inner_cylinder = cylinders[0]
            outer_cylinder = cylinders[1]

            hole_inner_radius = inner_cylinder['radius']
            hole_outer_radius = outer_cylinder['radius']
            hole_depth = outer_cylinder['height']

            # 检查小孔是否贯穿三棱柱
            if prism is not None and hasattr(prism.Shape, "BoundBox"):
                prism_bbox = prism.Shape.BoundBox
                inner_cylinder_bbox = inner_cylinder['obj'].Shape.BoundBox

                # 小孔底面是否与三棱柱底面接触
                bottom_contact = abs(inner_cylinder_bbox.ZMin - prism_bbox.ZMin) < 0.1

                # 小孔顶面是否高于或与大孔底面接触
                top_contact = inner_cylinder_bbox.ZMax >= outer_cylinder['obj'].Shape.BoundBox.ZMin

                inner_hole_through = bottom_contact and top_contact

        elif len(cylinders) == 1:
            cylinder = cylinders[0]
            hole_inner_radius = cylinder['radius']

            if prism is not None and hasattr(prism.Shape, "BoundBox"):
                prism_bbox = prism.Shape.BoundBox
                cylinder_bbox = cylinder['obj'].Shape.BoundBox

                # 小孔底面是否与三棱柱底面接触
                bottom_contact = abs(cylinder_bbox.ZMin - prism_bbox.ZMin) < 0.1

                # 小孔顶面是否高于或与大孔底面接触（假设只有一个孔时，顶面与三棱柱顶面接触）
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
                        message: `检测到${FUNCTION_BEHAVIOR}操作`,
                        filename: this.filename,
                        code: pythonCode
                    });
                }
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
