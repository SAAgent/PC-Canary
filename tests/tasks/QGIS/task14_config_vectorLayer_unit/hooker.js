// QGIS设置向量图层单位钩子脚本
// 用于监听QGIS的设置向量图层单位操作并检测相关参数

(function () {
    // 脚本常量设置
    const SYMBOL_NAME = "_ZNK9QgsSymbol13setOutputUnitEN4Qgis10RenderUnitE"; // QgsSymbol::setOutputUnit函数的符号

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
    
    // 单位枚举值映射到名称
    const unitNames = {
        0: "Millimeters",
        1: "MapUnits",
        2: "Pixels",
        3: "Percentage",
        4: "Points",
        5: "Inches"
    };

    // 初始化钩子并立即执行
    function initHook() {
        sendEvent("script_initialized", {
            message: "QGIS向量图层单位设置监控脚本已启动"
        });

        // 查找setOutputUnit函数
        let setUnitAddr = Module.findExportByName(null, SYMBOL_NAME);

        // 如果没找到，尝试扫描所有加载的模块
        if (!setUnitAddr) {
            sendEvent("function_search_start", {
                message: "正在查找QgsSymbol::setOutputUnit函数..."
            });

            // 遍历模块
            Process.enumerateModules({
                onMatch: function (module) {
                    if (module.name.includes("qgis_core")) {
                        sendEvent("module_found", {
                            module_name: module.name,
                            base_address: module.base.toString()
                        });

                        // 在qgis_core模块中查找符号
                        const symbol = module.findExportByName(SYMBOL_NAME);
                        if (symbol) {
                            setUnitAddr = symbol;
                        }
                    }
                },
                onComplete: function () { }
            });

            // 如果仍未找到，报告错误
            if (!setUnitAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "无法找到QgsSymbol::setOutputUnit函数"
                });
                return;
            }
        }

        // 报告找到函数
        sendEvent("set_function_found", {
            address: setUnitAddr.toString(),
            message: "找到QgsSymbol::setOutputUnit函数"
        });
        
        // 安装钩子
        Interceptor.attach(setUnitAddr, {
            onEnter: function(args) {
                try {
                    // 获取this指针和枚举参数
                    const thisPtr = args[0];
                    const unitValue = parseInt(args[1].toString());
                    
                    // 获取图层名称
                    const layerPtr = thisPtr.add(0x58).readPointer();
                    if (!layerPtr.isNull()) {
                        const nameQString = layerPtr.add(0x20);
                        const layerName = qstringToString(nameQString);

                        console.log("设置图层单位,图层名称为:", layerName);

                        // 发送图层名称事件
                        sendEvent("layer_set", {
                            name: layerName,
                            message: `检测到设置单位的图层,名称为:${layerName}`
                        });

                        // 将枚举值转换为单位名称
                        const unitName = unitNames[unitValue] || `未知单位(${unitValue})`;
                        console.log("设置单位为:", unitName, "原始枚举值:", unitValue);

                        // 发送单位事件
                        sendEvent("unit_set", {
                            layer: layerName,
                            unit: unitName,
                            unit_value: unitValue,
                            message: `检测到设置图层 ${layerName} 的单位为: ${unitName}`
                        });
                    }
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
            message: "钩子安装完成，等待设置图层单位操作..."
        });
    }

    // 立即执行钩子初始化
    initHook();
})();