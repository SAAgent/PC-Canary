// QGIS调整图层次序钩子脚本
// 用于监听QGIS的调整图层次序操作并检测相关参数

(function() {
    // 脚本常量设置
    const SYMBOL_NAME = "_ZN12QgsLayerTree19setCustomLayerOrderERK5QListIP11QgsMapLayerE"; // QgsLayerTree::setCustomLayerOrder的函数符号
    
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
        try {
            const d = qstr.readPointer();                         // QString::d
            const len = d.add(SIZE_OFFSET).readU32();             // QStringData::size
            const data = d.add(HEADER_SIZE);                      // first UTF‑16 char
            return Memory.readUtf16String(data, len);
        } catch (error) {
            console.log("解析QString失败:", error);
            return "";
        }
    }

    // 初始化钩子并立即执行
    function initHook() {
        sendEvent("script_initialized", {
            message: "QGIS图层次序监控脚本已启动"
        });
        
        // 查找setCustomLayerOrder函数
        let setOrderAddr = Module.findExportByName(null, SYMBOL_NAME);
        
        // 如果没找到，尝试扫描所有加载的模块
        if (!setOrderAddr) {
            sendEvent("function_search_start", {
                message: "正在查找QgsLayerTree::setCustomLayerOrder函数..."
            });
            
            // 遍历模块
            Process.enumerateModules({
                onMatch: function(module) {
                    if (module.name.includes("qgis_core")) {
                        sendEvent("module_found", {
                            module_name: module.name,
                            base_address: module.base.toString()
                        });
                        
                        // 在qgis模块中查找符号
                        const symbol = module.findExportByName(SYMBOL_NAME);
                        if (symbol) {
                            setOrderAddr = symbol;
                        }
                    }
                },
                onComplete: function() {}
            });
            
            // 如果仍未找到，报告错误
            if (!setOrderAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "无法找到QgsLayerTree::setCustomLayerOrder函数"
                });
                return;
            }
        }
        
        // 报告找到函数
        sendEvent("setOrder_function_found", {
            address: setOrderAddr.toString(),
            message: "找到QgsLayerTree::setCustomLayerOrder函数"
        });
        
        // 安装钩子
        Interceptor.attach(setOrderAddr, {
            onEnter: function(args) {
                try {
                    // 获取QList<QgsMapLayer *>参数
                    const qlistPtr = args[1]; // 参数数组的第二个参数(customLayerOrder)
                    
                    // 读取QList的begin和end，计算元素个数
                    const begin = qlistPtr.readPointer().add(0x8).readU32();
                    const end = qlistPtr.readPointer().add(0xc).readU32();
                    const count = end - begin;
                    console.log(`图层次序列表包含 ${count} 个图层`);
                    
                    // 提取所有图层的名称
                    const layerNames = [];
                    
                    for (let i = 0; i < count; i++) {
                        // 计算当前元素在QList中的偏移
                        const elementOffset = 0x10 + (i * Process.pointerSize);
                        // 读取当前图层指针
                        const layerPtr = qlistPtr.readPointer().add(elementOffset).readPointer();
                        // 读取图层名称 (偏移0x20处是图层名称的QString)
                        const nameQString = layerPtr.add(0x20);
                        const name = qstringToString(nameQString);
                        
                        layerNames.push(name);
                        console.log(`图层 ${i+1}: ${name}`);
                    }
                    
                    // 发送事件通知
                    sendEvent("order_set", {
                        layer_count: count,
                        layer_names: layerNames,
                        order_string: layerNames.join(','),
                        message: `检测到图层次序变更: ${layerNames.join(',')}`
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
            message: "钩子安装完成，等待图层次序调整操作..."
        });
    }
    
    // 立即执行钩子初始化
    initHook();
})();