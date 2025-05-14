// QGIS设置向量图层颜色钩子脚本
// 用于监听QGIS的设置向量图层颜色操作并检测相关参数

(function() {
    // 脚本常量设置
    const SYMBOL_NAME = "_ZN20QgsSymbolsListWidget14setSymbolColorERK6QColor"; // QgsSymbolsListWidget::setSymbolColor函数的符号
    
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
    // 将QColor转换为十六进制字符串
    function qColorToHex(r, g, b) {
        const toHex = (val) => 
            Math.round( (val/65535)*255 )
                .toString(16)
                .padStart(2, '0')
                .toUpperCase()
        
        return `#${toHex(r)}${toHex(g)}${toHex(b)}`
    }

    // 初始化钩子并立即执行
    function initHook() {
        sendEvent("script_initialized", {
            message: "QGIS向量图层颜色设置监控脚本已启动"
        });
        
        // 查找setSymbolColor函数
        let setColorAddr = Module.findExportByName(null, SYMBOL_NAME);
        
        // 如果没找到，尝试扫描所有加载的模块
        if (!setColorAddr) {
            sendEvent("function_search_start", {
                message: "正在查找QgsSymbolsListWidget::setSymbolColor函数..."
            });
            
            // 遍历模块
            Process.enumerateModules({
                onMatch: function(module) {
                    if (module.name.includes("qgis_gui")) {
                        sendEvent("module_found", {
                            module_name: module.name,
                            base_address: module.base.toString()
                        });
                        
                        // 在qgis_gui模块中查找符号
                        const symbol = module.findExportByName(SYMBOL_NAME);
                        if (symbol) {
                            setColorAddr = symbol;
                        }
                    }
                },
                onComplete: function() {}
            });
            
            // 如果仍未找到，报告错误
            if (!setColorAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "无法找到QgsSymbolsListWidget::setSymbolColor函数"
                });
                return;
            }
        }
        
        // 报告找到函数
        sendEvent("set_function_found", {
            address: setColorAddr.toString(),
            message: "找到QgsSymbolsListWidget::setSymbolColor函数"
        });
        
        // 安装钩子
        Interceptor.attach(setColorAddr, {
            onEnter: function(args) {
                try {
                    // 获取this指针，读取图层名称
                    const thisPtr = args[0];
                    // 图层名称在this+0x1f0处readpointer之后再+0x20
                    const layerPtr = thisPtr.add(0x1f0).readPointer();
                    const nameQString = layerPtr.add(0x20);
                    const layerName = qstringToString(nameQString);
                    
                    console.log("设置图层颜色,图层名称为:", layerName);
                    
                    // 发送图层名称事件
                    sendEvent("layer_set", {
                        name: layerName,
                        message: `检测到设置颜色的图层,名称为:${layerName}`
                    });
                    
                    // 获取颜色参数(QColor)
                    const colorPtr = args[1];
                    // 读取RGBA值
                    const alpha = colorPtr.add(0x4).readU16();
                    const red = colorPtr.add(0x6).readU16();
                    const green = colorPtr.add(0x8).readU16();
                    const blue = colorPtr.add(0xa).readU16();
                    
                    // 转换为十六进制表示
                    const hexColor = qColorToHex(red, green, blue);
                    
                    console.log("设置颜色为:", hexColor, "RGBA:", red, green, blue, alpha);
                    
                    // 发送颜色事件
                    sendEvent("color_set", {
                        layer: layerName,
                        color: hexColor,
                        rgba: {
                            red: red,
                            green: green,
                            blue: blue,
                            alpha: alpha
                        },
                        message: `检测到设置图层 ${layerName} 的颜色为: ${hexColor}`
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
            message: "钩子安装完成，等待设置图层颜色操作..."
        });
    }
    
    // 立即执行钩子初始化
    initHook();
})();