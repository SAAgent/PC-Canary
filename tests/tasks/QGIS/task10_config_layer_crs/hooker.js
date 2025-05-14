// QGIS配置Crs钩子脚本
// 用于监听QGIS的配置CRS操作并检测是否更新

(function() {
    // 脚本常量设置
    const SYMBOL_NAME = "_ZN11QgsMapLayer6setCrsERK28QgsCoordinateReferenceSystemb"; // setCrs函数的符号
    
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
            message: "QGIS CRS监控脚本已启动"
        });
        
        // 查找setCrs函数
        let setCrsFuncAddr = Module.findExportByName(null, SYMBOL_NAME);
        
        // 如果没找到，尝试扫描所有加载的模块
        if (!setCrsFuncAddr) {
            sendEvent("function_search_start", {
                message: "正在查找QgsMapLayer::setCrs函数..."
            });
            
            // 遍历模块
            Process.enumerateModules({
                onMatch: function(module) {
                    if (module.name.includes("qgis_core")) {
                        sendEvent("module_found", {
                            module_name: module.name,
                            base_address: module.base.toString()
                        });
                        
                        // 在qgis_core模块中查找符号
                        const symbol = module.findExportByName(SYMBOL_NAME);
                        if (symbol) {
                            setCrsFuncAddr = symbol;
                        }
                    }
                },
                onComplete: function() {}
            });
            
            // 如果仍未找到，报告错误
            if (!setCrsFuncAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "无法找到QgsMapLayer::setCrs函数"
                });
                return;
            }
        }
        
        // 报告找到函数
        sendEvent("modifyCrs_function_found", {
            address: setCrsFuncAddr.toString(),
            message: "找到QgsMapLayer::setCrs函数"
        });
        
        // 安装钩子
        Interceptor.attach(setCrsFuncAddr, {
            onEnter: function(args) {
                try {
                    // 获取图层名称 (this指针)
                    const thisPtr = args[0];
                    // 图层名称在this+0x20位置
                    const nameQString = thisPtr.add(0x20);
                    const layerName = qstringToString(nameQString);
                    console.log("图层名称:", layerName);
                    
                    // 首先发送图层名称事件
                    sendEvent("layerName_found", {
                        name: layerName,
                        message: `检测到操作图层: ${layerName}`
                    });
                    
                    // 获取CRS参数
                    const crsPtr = args[1];
                    // 获取d指针
                    const dPtr = crsPtr.readPointer();
                    
                    // 逆向确定mSRID的偏移量
                    const mSRID = dPtr.add(56).readInt();
                    console.log("mSRID:", mSRID);
                    
                    // 发送CRS变更事件
                    sendEvent("newCrs_detected", {
                        layer: layerName,
                        crs: mSRID,
                        message: `检测到图层 ${layerName} CRS更改为: ${mSRID}`
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
            message: "钩子安装完成，等待CRS变更操作..."
        });
    }
    
    // 立即执行钩子初始化
    initHook();
})();