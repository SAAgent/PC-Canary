// QGIS导出地图图像钩子脚本
// 用于监听QGIS导出地图为图片的相关操作并检测参数

(function() {
    // 脚本常量设置
    const setPathandType_SYMBOL_NAME="_ZN11QgsGuiUtils18getSaveAsImageNameEP7QWidgetRK7QStringS4_" // QgsGuiUtils::getSaveAsImageName 函数的符号
    const setPathandType_SYMBOL_NAME2="_ZNK6QImage4saveERK7QStringPKci" // QImage::save 函数的符号
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
            message: "QGIS导出地图图像监控脚本已启动"
        });
        
        // 查找设置路径和类型的函数
        let setPathandTypeAddr = Module.findExportByName(null, setPathandType_SYMBOL_NAME);
        
        // 如果没找到，尝试扫描所有加载的模块
        if (!setPathandTypeAddr) {
            sendEvent("function_search_start", {
                message: "正在查找QgsGuiUtils::getSaveAsImageName函数..."
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
                        const symbol = module.findExportByName(setPathandType_SYMBOL_NAME);
                        if (symbol) {
                            setPathandTypeAddr = symbol;
                        }
                    }
                },
                onComplete: function() {}
            });
            
            // 如果仍未找到，报告错误
            if (!setPathandTypeAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "无法找到QgsGuiUtils::getSaveAsImageName函数"
                });
            }
        }
        
        // 如果找到了第一个函数，报告并安装钩子
        if (setPathandTypeAddr) {
            // 报告找到函数
            sendEvent("setPathandType_function_found", {
                address: setPathandTypeAddr.toString(),
                message: "找到QgsGuiUtils::getSaveAsImageName函数"
            });
            
            // 安装钩子 - 设置路径和类型
            Interceptor.attach(setPathandTypeAddr, {
                onLeave: function(retval) {
                    try {
                        // 获取QPair<QString, QString>的返回值
                        const pairPtr = retval;
                        
                        // 读取第一个QString - 文件路径
                        const pathQString = pairPtr;
                        const filePath = qstringToString(pathQString);
                        
                        // 读取第二个QString - 文件类型
                        const typeQString = pairPtr.add(Process.pointerSize); // QString的大小通常是指针大小的4倍
                        const fileType = qstringToString(typeQString);
                        
                        console.log("导出图片路径:", filePath, "类型:", fileType);
                        
                        // 发送事件通知
                        sendEvent("PathandType_set", {
                            path: filePath,
                            type: fileType,
                            message: `检测到导出图片设置: 路径=${filePath}, 类型=${fileType}`
                        });
                    } catch (error) {
                        sendEvent("error", {
                            error_type: "hook_execution_error",
                            message: `获取路径和类型时出错: ${error.message}`,
                            stack: error.stack
                        });
                    }
                }
            });
        }
        
        // 查找QImage::save函数
        let imageSaveAddr = Module.findExportByName(null, setPathandType_SYMBOL_NAME2);
        
        // 如果没找到，尝试扫描所有加载的模块
        if (!imageSaveAddr) {
            sendEvent("function_search_start", {
                message: "正在查找QImage::save函数..."
            });
            
            // 遍历模块
            Process.enumerateModules({
                onMatch: function(module) {
                    if (module.name.includes("Qt5")) {
                        sendEvent("module_found", {
                            module_name: module.name,
                            base_address: module.base.toString()
                        });
                        
                        // 在Qt5模块中查找符号
                        const symbol = module.findExportByName(setPathandType_SYMBOL_NAME2);
                        if (symbol) {
                            imageSaveAddr = symbol;
                        }
                    }
                },
                onComplete: function() {}
            });
            
            // 如果仍未找到，报告错误
            if (!imageSaveAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "无法找到QImage::save函数"
                });

            }
        }
        
        // 如果找到了QImage::save函数，报告并安装钩子
        if (imageSaveAddr) {
            // 报告找到函数
            sendEvent("image_save_function_found", {
                address: imageSaveAddr.toString(),
                message: "找到QImage::save函数"
            });
            
            // 安装钩子 - QImage::save
            Interceptor.attach(imageSaveAddr, {
                onEnter: function(args) {
                    try {
                        // 获取第一个参数 - 文件路径（const QString &fileName）
                        const pathQString = args[1]; // 
                        const filePath = qstringToString(pathQString);
                        
                        // 从文件路径获取扩展名作为类型
                        let fileType = "";
                        const lastDotIndex = filePath.lastIndexOf('.');
                        if (lastDotIndex !== -1 && lastDotIndex < filePath.length - 1) {
                            fileType = filePath.substring(lastDotIndex + 1).toLowerCase();
                        }
                        
                        console.log("QImage保存图片路径:", filePath, "类型:", fileType);
                        
                        // 发送事件通知
                        sendEvent("PathandType_set", {
                            path: filePath,
                            type: fileType,
                            message: `检测到QImage保存图片: 路径=${filePath}, 类型=${fileType}`
                        });
                    } catch (error) {
                        sendEvent("error", {
                            error_type: "hook_execution_error",
                            message: `获取QImage::save路径和类型时出错: ${error.message}`,
                            stack: error.stack
                        });
                    }
                }
            });
        }
        
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
                    
                    console.log("导出图片尺寸: 宽=", width, "高=", height);
                    
                    // 发送事件通知
                    sendEvent("Size_set", {
                        width: width,
                        height: height,
                        message: `检测到图片尺寸设置: 宽=${width}px, 高=${height}px`
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
            message: "钩子安装完成，等待导出地图操作..."
        });
    }
    
    // 立即执行钩子初始化
    initHook();
})();