// QGIS图层添加钩子脚本
// 用于监听QGIS的添加向量图层操作并检测相关参数

(function() {
    // 脚本常量设置
    const SYMBOL_NAME = "_ZN10QgsProject11addMapLayerEP11QgsMapLayerbb"; // QgsProject::addMapLayer函数的符号
    
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
            message: "QGIS向量图层添加监控脚本已启动"
        });
        
        // 查找addVectorLayer函数
        let addVectorLayerAddr = Module.findExportByName(null, SYMBOL_NAME);
        
        // 如果没找到，尝试扫描所有加载的模块
        if (!addVectorLayerAddr) {
            sendEvent("function_search_start", {
                message: "正在查找QgsProject::addMapLayer函数..."
            });
            
            // 遍历模块
            Process.enumerateModules({
                onMatch: function(module) {
                    if (module.name.includes("qgis_app") ) {
                        sendEvent("module_found", {
                            module_name: module.name,
                            base_address: module.base.toString()
                        });
                        
                        // 在qgis_app模块中查找符号
                        const symbol = module.findExportByName(SYMBOL_NAME);
                        if (symbol) {
                            addVectorLayerAddr = symbol;
                        }
                    }
                },
                onComplete: function() {}
            });
            
            // 如果仍未找到，报告错误
            if (!addVectorLayerAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "无法找到QgsProject::addMapLayer函数"
                });
                return;
            }
        }
        
        // 报告找到函数
        sendEvent("addvectorLayer_function_found", {
            address: addVectorLayerAddr.toString(),
            message: "找到QgsProject::addMapLayer函数"
        });
        
        // 安装钩子
        Interceptor.attach(addVectorLayerAddr, {
            onEnter: function(args) {
                try {
                    const layerPointer = args[1];
                    const uriQString = layerPointer.add(0x18); 
                    const uri = qstringToString(uriQString);
                    console.log("添加向量图层,路径为:", uri);
                    // 发送事件通知
                    sendEvent("vector_layer_added", {
                        uri: uri,
                        message: `检测到添加向量图层,路径为:${uri}`
                    });
                } catch (error) {
                    sendEvent("error", {
                        error_type: "hook_execution_error",
                        message: `执行钩子时出错: ${error.message}`,
                    });
                }
            }
            
        });
        
        sendEvent("hook_installed", {
            message: "钩子安装完成，等待添加向量图层操作..."
        });
    }
    
    // 立即执行钩子初始化
    initHook();
})();