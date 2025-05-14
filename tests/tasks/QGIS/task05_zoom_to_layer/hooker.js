// QGIS缩放到图层钩子脚本
// 用于监听QGIS的缩放到图层操作并检测相关参数

(function() {
    // 脚本常量设置
    const SYMBOL_NAME = "_ZN30QgsLayerTreeViewDefaultActions12zoomToLayersEP12QgsMapCanvasRK5QListIP11QgsMapLayerE"; // QgsLayerTreeViewDefaultActions::zoomToLayers 函数的符号
    
    // 向评估系统发送事件
    function sendEvent(eventType, data = {}) {
        const payload = {
            event: eventType,
            ...data,
            timestamp: new Date().getTime()
        };
        send(payload);
    }
    
    const HEADER_SIZE = 24;   
    const SIZE_OFFSET = 4;                  

    function qstringToString(qstr) {
        const d    = qstr.readPointer();                         // QString::d
        const len  = d.add(SIZE_OFFSET).readU32();               // QStringData::size
        const data = d.add(HEADER_SIZE);                         // first UTF‑16 char
        return Memory.readUtf16String(data, len);
    }

    // 初始化钩子并立即执行
    function initHook() {
        sendEvent("script_initialized", {
            message: "QGIS图层缩放监控脚本已启动"
        });
        
        // 查找zoomToLayers函数
        let zoomToLayersAddr = Module.findExportByName(null, SYMBOL_NAME);
        
        // 如果没找到，尝试扫描所有加载的模块
        if (!zoomToLayersAddr) {
            sendEvent("function_search_start", {
                message: "正在查找QgsLayerTreeViewDefaultActions::zoomToLayers函数..."
            });
            
            // 遍历模块
            Process.enumerateModules({
                onMatch: function(module) {
                    if (module.name.includes("qgis_gui")) {
                        sendEvent("module_found", {
                            module_name: module.name,
                            base_address: module.base.toString()
                        });
                        
                        // 在qgis模块中查找符号
                        const symbol = module.findExportByName(SYMBOL_NAME);
                        if (symbol) {
                            zoomToLayersAddr = symbol;
                        }
                    }
                },
                onComplete: function() {}
            });
            
            // 如果仍未找到，报告错误
            if (!zoomToLayersAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "无法找到QgsLayerTreeViewDefaultActions::zoomToLayers函数"
                });
                return;
            }
        }
        
        // 报告找到函数
        sendEvent("zoom_function_found", {
            address: zoomToLayersAddr.toString(),
            message: "找到QgsLayerTreeViewDefaultActions::zoomToLayers函数"
        });
        
        // 安装钩子
        Interceptor.attach(zoomToLayersAddr, {
            onEnter: function(args) {
                try {
                    const layerPointer = args[2];
                    const nameQString = layerPointer.readPointer().add(0x10).readPointer().add(0x20); // 获取QString指针
                    const name = qstringToString(nameQString);
                    console.log("缩放图层,名称为:", name);
                    // 发送事件通知
                    sendEvent("layer_zoomed", {
                        name: name,
                        message: `检测到待缩放显示的图层,名称为:${name}`
                    });
                } catch (error) {
                    sendEvent("error", {
                        error_type: "hook_execution_error",
                        message: `执行钩子时出错: ${error.message}`,
                        stack: error.stack
                    });
                }
            }
        });
        
        sendEvent("hook_installed", {
            message: "钩子安装完成，等待缩放图层操作..."
        });
    }
    
    // 立即执行钩子初始化
    initHook();
})();