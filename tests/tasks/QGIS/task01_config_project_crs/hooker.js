// QGIS配置Crs钩子脚本
// 用于监听QGIS的配置CRS操作并检测是否更新

(function() {
    // 脚本常量设置
    const SYMBOL_NAME = "_ZN10QgsProject6setCrsERK28QgsCoordinateReferenceSystemb"; // setCrs函数的符号
    
    // 向评估系统发送事件
    function sendEvent(eventType, data = {}) {
        const payload = {
            event: eventType,
            ...data,
            timestamp: new Date().getTime()
        };
        send(payload);
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
                message: "正在查找QgsProject::setCrs函数..."
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
                    message: "无法找到QgsProject::setCrs函数"
                });
                return;
            }
        }
        
        // 报告找到函数
        sendEvent("setCrs_function_found", {
            address: setCrsFuncAddr.toString(),
            message: "找到QgsProject::setCrs函数"
        });
        
        // 安装钩子
        Interceptor.attach(setCrsFuncAddr, {
            onEnter: function(args) {
                try {
                    const crsPtr = args[1];
                    // 获取d指针
                    const dPtr = crsPtr.readPointer();
                    
                    // 逆向确定mSRID的偏移量
                    const mSRID = dPtr.add(56).readInt();
                    console.log("mSRID:", mSRID);
                    sendEvent("newCrs_detected", {
                        crs: mSRID,
                        message: `检测到CRS更改: crs=${mSRID}`
                    });
                } catch (error) {
                    sendEvent("error", {
                        error_type: "hook_execution_error",
                        message: `执行钩子时出错: ${error.message}`
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