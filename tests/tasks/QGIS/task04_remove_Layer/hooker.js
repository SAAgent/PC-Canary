// QGIS图层删除钩子脚本
// 用于监听QGIS的删除图层操作并检测相关参数

(function() {
    // 脚本常量设置
    const SYMBOL_NAME = "_ZN16QgsMapLayerStore15removeMapLayersERK5QListIP11QgsMapLayerE"; // QgsMapLayerStore::removeMapLayers函数的符号
    
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
            message: "QGIS图层删除监控脚本已启动"
        });
        
        // 查找addVectorLayer函数
        let removeLayersAddr = Module.findExportByName(null, SYMBOL_NAME);
        
        // 如果没找到，尝试扫描所有加载的模块
        if (!removeLayersAddr) {
            sendEvent("function_search_start", {
                message: "正在查找QgsMapLayerStore::removeMapLayers函数..."
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
                            removeLayersAddr = symbol;
                        }
                    }
                },
                onComplete: function() {}
            });
            
            // 如果仍未找到，报告错误
            if (!removeLayersAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "无法找到QgsMapLayerStore::removeMapLayers函数"
                });
                return;
            }
        }
        
        // 报告找到函数
        sendEvent("removeLayer_function_found", {
            address: removeLayersAddr.toString(),
            message: "找到QgsMapLayerStore::removeMapLayers函数"
        });
        
        // 安装钩子
        Interceptor.attach(removeLayersAddr, {
            onEnter: function(args) {
                try {
                    const layerPointer = args[1];
                    const nameQString = layerPointer.readPointer().add(0x10).readPointer().add(0x20); // 获取QString指针
                    const name = qstringToString(nameQString);
                    console.log("删除图层,名称为:", name);
                    // 发送事件通知
                    sendEvent("layer_removed", {
                        name: name,
                        message: `检测到删除图层,名称为:${name}`
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
            message: "钩子安装完成，等待删除图层操作..."
        });
    }
    
    // 立即执行钩子初始化
    initHook();
})();