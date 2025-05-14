// QGIS创建新项目钩子脚本
// 用于监听QGIS创建和保存新项目的操作并检测参数

(function() {
    // 脚本常量设置
    const clearProject_SYMBOL_NAME="_ZN10QgsProject5clearEv" // QgsProject::clear 函数的符号
    const setPath_SYMBOL_NAME="_ZN10QgsProject11setFileNameERK7QString" // QgsProject::setFileName 函数的符号
    
    // 计数器和时间戳，用于过滤启动时的自动调用
    let clearCounter = 0;
        
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
            message: "QGIS创建新项目监控脚本已启动"
        });
        
        // 查找创建新项目的函数 QgsProject::clear
        let clearProjectAddr = Module.findExportByName(null, clearProject_SYMBOL_NAME);
        
        // 如果没找到，尝试扫描所有加载的模块
        if (!clearProjectAddr) {
            sendEvent("function_search_start", {
                message: "正在查找QgsProject::clear函数..."
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
                        const symbol = module.findExportByName(clearProject_SYMBOL_NAME);
                        if (symbol) {
                            clearProjectAddr = symbol;
                        }
                    }
                },
                onComplete: function() {}
            });
            
            // 如果仍未找到，报告错误
            if (!clearProjectAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "无法找到QgsProject::clear函数"
                });
                return;
            }
        }
        
        // 报告找到函数
        sendEvent("clear_function_found", {
            address: clearProjectAddr.toString(),
            message: "找到QgsProject::clear函数"
        });
        
        // 查找保存项目的函数 QgsProject::setFileName
        let setFileNameAddr = Module.findExportByName(null, setPath_SYMBOL_NAME);
        
        // 如果没找到，尝试扫描所有加载的模块
        if (!setFileNameAddr) {
            sendEvent("function_search_start", {
                message: "正在查找QgsProject::setFileName函数..."
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
                        const symbol = module.findExportByName(setPath_SYMBOL_NAME);
                        if (symbol) {
                            setFileNameAddr = symbol;
                        }
                    }
                },
                onComplete: function() {}
            });
            
            // 如果仍未找到，报告错误
            if (!setFileNameAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "无法找到QgsProject::setFileName函数"
                });
                return;
            }
        }
        
        // 报告找到函数
        sendEvent("setPath_function_found", {
            address: setFileNameAddr.toString(),
            message: "找到QgsProject::setFileName函数"
        });
        
        // 安装钩子 - 创建新项目
        Interceptor.attach(clearProjectAddr, {
            onEnter: function(args) {
                try {
                    clearCounter++;
                    
                    
                    // 忽略启动时期的自动调用（计数器为1时的调用）
                    if (clearCounter > 1 ) {
                        console.log("检测到用户创建新项目");
                        
                        // 发送事件通知
                        sendEvent("newProject_created", {
                            message: "检测到创建新项目"
                        });
                    } else {
                        console.log("忽略应用启动时的项目初始化");
                    }
                } catch (error) {
                    sendEvent("error", {
                        error_type: "hook_execution_error",
                        message: `监控创建新项目时出错: ${error.message}`,
                        stack: error.stack
                    });
                }
            }
        });
        
        // 安装钩子 - 保存项目
        Interceptor.attach(setFileNameAddr, {
            onEnter: function(args) {
                try {
                    // 获取函数的第二个参数（const QString &name），第一个是this指针
                    const pathQString = args[1];
                    const filePath = qstringToString(pathQString);
                    
                    console.log("检测到保存项目路径:", filePath);
                    
                    // 发送事件通知
                    sendEvent("newProject_saved", {
                        path: filePath,
                        message: `检测到保存项目设置: 路径=${filePath}`
                    });
                } catch (error) {
                    sendEvent("error", {
                        error_type: "hook_execution_error",
                        message: `监控保存项目时出错: ${error.message}`,
                        stack: error.stack
                    });
                }
            }
        });
        
        sendEvent("hook_installed", {
            message: "钩子安装完成，等待创建和保存新项目操作..."
        });
    }
    
    // 立即执行钩子初始化
    initHook();
})();