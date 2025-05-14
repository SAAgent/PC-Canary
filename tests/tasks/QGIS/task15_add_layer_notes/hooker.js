
// QGIS添加图层注解钩子脚本
// 用于监听QGIS的添加图层注解操作并检测相关参数

(function () {
    // 脚本常量设置
    const SYMBOL_NAME = "_ZN18QgsLayerNotesUtils13setLayerNotesEP11QgsMapLayerRK7QString"; // QgsLayerNotesUtils::setLayerNotes函数的符号

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
    
    // 从HTML中提取纯文本内容
    function extractTextFromHtml(html) {
        try {
            // 提取<p>标签中的内容
            const matches = html.match(/<p[^>]*>(.*?)<\/p>/g);
            if (matches && matches.length > 0) {
                // 提取所有<p>标签中的文本并合并
                const textContents = matches.map(p => {
                    // 移除所有HTML标签
                    return p.replace(/<[^>]*>/g, '');
                });
                return textContents.join("\n");
            }
            
            // 如果没有找到<p>标签，则移除所有标签返回纯文本
            return html.replace(/<[^>]*>/g, '');
        } catch (error) {
            console.log("提取文本失败:", error);
            return html;
        }
    }

    // 初始化钩子并立即执行
    function initHook() {
        sendEvent("script_initialized", {
            message: "QGIS图层注解监控脚本已启动"
        });

        // 查找setLayerNotes函数
        let setNotesAddr = Module.findExportByName(null, SYMBOL_NAME);

        // 如果没找到，尝试扫描所有加载的模块
        if (!setNotesAddr) {
            sendEvent("function_search_start", {
                message: "正在查找QgsLayerNotesUtils::setLayerNotes函数..."
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
                            setNotesAddr = symbol;
                        }
                    }
                },
                onComplete: function () { }
            });

            // 如果仍未找到，报告错误
            if (!setNotesAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "无法找到QgsLayerNotesUtils::setLayerNotes函数"
                });
                return;
            }
        }

        // 报告找到函数
        sendEvent("set_function_found", {
            address: setNotesAddr.toString(),
            message: "找到QgsLayerNotesUtils::setLayerNotes函数"
        });
        
        // 安装钩子
        Interceptor.attach(setNotesAddr, {
            onEnter: function(args) {
                try {
                    // 获取参数：layer和notes(由于是类调用吗，不存在this指针)
                    // args[0]是QgsLayer的指针，args[1]是QString的指针
                    const layerPtr = args[0];  
                    const notesQString = args[1];
                    console.log("添加图层注解,参数为:", layerPtr);
                    if (!layerPtr.isNull()) {
                        // 获取图层名称
                        const nameQString = layerPtr.add(0x20);
                        console.log("图层名称指针:", nameQString);
                        const layerName = qstringToString(nameQString);

                        console.log("添加图层注解,图层名称为:", layerName);

                        // 发送图层名称事件
                        sendEvent("layer_set", {
                            name: layerName,
                            message: `检测到添加注解的图层,名称为:${layerName}`
                        });
                        
                        // 获取注解内容
                        const notesHtml = qstringToString(notesQString);
                        const notesText = extractTextFromHtml(notesHtml);
                        
                        console.log("添加的注解内容为:", notesText);
                        console.log("原始HTML:", notesHtml);

                        // 发送注解内容事件
                        sendEvent("notes_set", {
                            layer: layerName,
                            notes: notesText,
                            notes_html: notesHtml,
                            message: `检测到为图层 ${layerName} 添加注解: ${notesText}`
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
            message: "钩子安装完成，等待添加图层注解操作..."
        });
    }

    // 立即执行钩子初始化
    initHook();
})();