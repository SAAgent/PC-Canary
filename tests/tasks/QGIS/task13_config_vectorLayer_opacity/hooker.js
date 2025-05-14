// QGIS设置向量图层不透明度钩子脚本
// 用于监听QGIS的设置向量图层不透明度操作并检测相关参数

(function () {
    // 脚本常量设置
    const SYMBOL_NAME = "_ZN9QgsSymbol10setOpacityEd"; // QgsSymbol::setOpacity函数的符号

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
            message: "QGIS向量图层不透明度设置监控脚本已启动"
        });

        // 查找setOpacity函数
        let setOpacityAddr = Module.findExportByName(null, SYMBOL_NAME);

        // 如果没找到，尝试扫描所有加载的模块
        if (!setOpacityAddr) {
            sendEvent("function_search_start", {
                message: "正在查找QgsSymbol::setOpacity函数..."
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
                            setOpacityAddr = symbol;
                        }
                    }
                },
                onComplete: function () { }
            });

            // 如果仍未找到，报告错误
            if (!setOpacityAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "无法找到QgsSymbol::setOpacity函数"
                });
                return;
            }
        }

        // 报告找到函数
        sendEvent("set_function_found", {
            address: setOpacityAddr.toString(),
            message: "找到QgsSymbol::setOpacity函数"
        });

        // 保存原始函数
        const originalFunction = new NativeFunction(setOpacityAddr, 'void', ['pointer', 'double']);

        // 使用replace替代attach，并明确指定函数签名
        Interceptor.replace(setOpacityAddr, new NativeCallback(function (thisPtr, opacity) {
            try {
                // 获取图层名称
                const layerPtr = thisPtr.add(0x58).readPointer();
                if (!layerPtr.isNull()) {
                    const nameQString = layerPtr.add(0x20);
                    const layerName = qstringToString(nameQString);

                    console.log("设置图层不透明度,图层名称为:", layerName);

                    // 发送图层名称事件
                    sendEvent("layer_set", {
                        name: layerName,
                        message: `检测到设置不透明度的图层,名称为:${layerName}`
                    });

                    // 现在opacity是正确传递的浮点数值
                    // 将0-1范围的不透明度转换为0-100%
                    const opacityPercent = (opacity * 100).toFixed(1);
                    console.log("设置不透明度为:", opacityPercent, "%", "原始值:", opacity);

                    // 发送不透明度事件
                    sendEvent("opacity_set", {
                        layer: layerName,
                        opacity: opacityPercent,
                        opacity_raw: opacity,
                        message: `检测到设置图层 ${layerName} 的不透明度为: ${opacityPercent}%`
                    });
                }
            } catch (error) {
                sendEvent("error", {
                    error_type: "hook_execution_error",
                    message: `执行钩子时出错: ${error.message}`,
                    stack: error.stack
                });
            }

            // 调用原始函数，保持原有功能
            return originalFunction(thisPtr, opacity);
        }, 'void', ['pointer', 'double']));

        sendEvent("hook_installed", {
            message: "钩子安装完成，等待设置图层不透明度操作..."
        });
    }

    // 立即执行钩子初始化
    initHook();
})();