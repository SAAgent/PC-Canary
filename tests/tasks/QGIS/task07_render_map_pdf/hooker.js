// QGIS导出地图PDF钩子脚本
// 用于监听QGIS导出地图为PDF的相关操作并检测参数

(function() {
    // 脚本常量设置
    const setPath_SYMBOL_NAME="_ZN11QFileDialog15getSaveFileNameEP7QWidgetRK7QStringS4_S4_PS2_6QFlagsINS_6OptionEE" // QFileDialog::getSaveFileName 函数的符号
    const setSize_SYMBOL_NAME="_ZN14QgsMapSettings13setOutputSizeE5QSize" // QgsMapSettings::setOutputSize 函数的符号
        
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
            message: "QGIS导出地图PDF监控脚本已启动"
        });
        
        // 查找设置路径的函数
        let setPathAddr = Module.findExportByName(null, setPath_SYMBOL_NAME);
        
        // 如果没找到，尝试扫描所有加载的模块
        if (!setPathAddr) {
            sendEvent("function_search_start", {
                message: "正在查找QFileDialog::getSaveFileName函数..."
            });
            
            // 遍历模块
            Process.enumerateModules({
                onMatch: function(module) {
                    if (module.name.includes("Qt5") || module.name.includes("libQt5")) {
                        sendEvent("module_found", {
                            module_name: module.name,
                            base_address: module.base.toString()
                        });
                        
                        // 在Qt5模块中查找符号
                        const symbol = module.findExportByName(setPath_SYMBOL_NAME);
                        if (symbol) {
                            setPathAddr = symbol;
                        }
                    }
                },
                onComplete: function() {}
            });
            
            // 如果仍未找到，报告错误
            if (!setPathAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "无法找到QFileDialog::getSaveFileName函数"
                });
                return;
            }
        }
        
        // 报告找到函数
        sendEvent("setPath_function_found", {
            address: setPathAddr.toString(),
            message: "找到QFileDialog::getSaveFileName函数"
        });
        
        // 查找设置尺寸的函数
        let setSizeAddr = Module.findExportByName(null, setSize_SYMBOL_NAME);
        
        // 如果没找到，尝试扫描所有加载的模块
        if (!setSizeAddr) {
            sendEvent("function_search_start", {
                message: "正在查找QgsMapSettings::setOutputSize函数..."
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
                        const symbol = module.findExportByName(setSize_SYMBOL_NAME);
                        if (symbol) {
                            setSizeAddr = symbol;
                        }
                    }
                },
                onComplete: function() {}
            });
            
            // 如果仍未找到，报告错误
            if (!setSizeAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "无法找到QgsMapSettings::setOutputSize函数"
                });
                return;
            }
        }
        
        // 报告找到函数
        sendEvent("setSize_function_found", {
            address: setSizeAddr.toString(),
            message: "找到QgsMapSettings::setOutputSize函数"
        });
        
        // 安装钩子 - 设置路径
        Interceptor.attach(setPathAddr, {
            onLeave: function(retval) {
                try {
                    // QFileDialog::getSaveFileName返回一个QString
                    const pathQString = retval;
                    const filePath = qstringToString(pathQString);
                    
                   
                    console.log("导出PDF路径:", filePath);
                    
                    // 发送事件通知
                    sendEvent("PathandType_set", {
                        path: filePath,
                        message: `检测到导出PDF设置: 路径=${filePath}`
                    });
                } catch (error) {
                    sendEvent("error", {
                        error_type: "hook_execution_error",
                        message: `获取路径时出错: ${error.message}`,
                        stack: error.stack
                    });
                }
            }
        });
        
        // 安装钩子 - 设置尺寸
        Interceptor.attach(setSizeAddr, {
            onEnter: function(args) {
                try {
                    //按照 System V AMD64 ABI 的第 3.2.3 节，对于小于或等于 16 字节的结构体，如果结构体所有字段均属于整型或指针，
                    //则整个结构体被划分为一个或多个 8 字节块，每块均归入 INTEGER 类，通过整数寄存器传递。
                    // 先把 NativePointer 转为无符号 64 位 BigInt
                    // 1. 拿到十六进制字符串，去掉前缀 "0x"
                    let hex = args[1].toString(16);
                    if (hex.startsWith("0x")) { hex = hex.slice(2); }

                    // 2. 补全到 16 位（8 字节）长度
                    hex = hex.padStart(16, "0");

                    // 3. 高 8 字节 = height，低 8 字节 = width
                    const hi = hex.slice(0, 8);
                    const lo = hex.slice(8);

                    const height = parseInt(hi, 16);
                    const width  = parseInt(lo, 16);
                    
                    console.log("导出PDF尺寸: 宽=", width, "高=", height);
                    
                    // 发送事件通知
                    sendEvent("Size_set", {
                        width: width,
                        height: height,
                        message: `检测到PDF尺寸设置: 宽=${width}px, 高=${height}px`
                    });
                } catch (error) {
                    sendEvent("error", {
                        error_type: "hook_execution_error",
                        message: `获取尺寸时出错: ${error.message}`,
                        stack: error.stack
                    });
                }
            }
        });
        
        sendEvent("hook_installed", {
            message: "钩子安装完成，等待导出PDF操作..."
        });
    }
    
    // 立即执行钩子初始化
    initHook();
})();