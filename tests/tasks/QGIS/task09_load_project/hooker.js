// QGIS加载项目钩子脚本
// 用于监听QGIS加载项目操作并检测相关参数

(function() {
    // 脚本常量设置
    const SYMBOL_NAME = "_ZN10QgsProject4readERK7QString6QFlagsIN4Qgis15ProjectReadFlagEE"; // QgsProject::read(QString, Qgis::ProjectReadFlags)的符号
    
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
            message: "QGIS加载项目监控脚本已启动"
        });
        
        // 查找加载项目函数
        let loadProjectAddr = Module.findExportByName(null, SYMBOL_NAME);
        
        // 如果没找到，尝试扫描所有加载的模块
        if (!loadProjectAddr) {
            sendEvent("function_search_start", {
                message: "正在查找QgsProject::read函数..."
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
                            loadProjectAddr = symbol;
                        }
                    }
                },
                onComplete: function() {}
            });
            
            // 如果仍未找到，报告错误
            if (!loadProjectAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "无法找到QgsProject::read函数"
                });
                return;
            }
        }
        
        // 报告找到函数
        sendEvent("load_function_found", {
            address: loadProjectAddr.toString(),
            message: "找到QgsProject::read函数"
        });
        
        // 安装钩子
        Interceptor.attach(loadProjectAddr, {
            onEnter: function(args) {
                try {
                    // 获取第二个参数（const QString &filename），第一个是this指针
                    const pathQString = args[1];
                    const filePath = qstringToString(pathQString);
                    
                    console.log("加载项目路径:", filePath);
                    
                    // 发送事件通知
                    sendEvent("project_loaded", {
                        path: filePath,
                        message: `检测到加载项目: 路径=${filePath}`
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
            message: "钩子安装完成，等待加载项目操作..."
        });
    }
    
    // 立即执行钩子初始化
    initHook();
})();