// 用于监听 GIMP 打开文件的函数调用

(function () {
    // 调试日志前缀
    const DEBUG_PREFIX = "[GIMP-HOOK-DEBUG]";

    // 向外部系统发送事件
    function sendEvent(eventType, data = {}) {
        const payload = {
            event_type: eventType,
            ...data,
            timestamp: new Date().getTime()
        };
        console.log(`${DEBUG_PREFIX} 发送事件: ${eventType}`, payload);
        send(payload);
    }

    // 通过符号名称查找函数地址
    function findFunctionAddress(symbolName) {
        try {
            // 获取主程序模块
            const mainModule = Process.enumerateModules()[0];
            if (!mainModule) {
                console.log(`${DEBUG_PREFIX} 错误: 未找到主程序模块`);
                sendEvent("error", {
                    message: "无法找到主程序模块",
                    error_type: "module_not_found"
                });
                return null;
            }

            console.log(`${DEBUG_PREFIX} 正在搜索模块: ${mainModule.name}`);

            // 枚举所有符号
            const symbols = Module.enumerateSymbols(mainModule.name);
            console.log(`${DEBUG_PREFIX} 找到 ${symbols.length} 个符号`);

            // 查找匹配的符号
            const targetSymbol = symbols.find(symbol => 
                symbol.name && symbol.name.includes(symbolName)
            );

            if (targetSymbol) {
                console.log(`${DEBUG_PREFIX} 找到目标符号: ${targetSymbol.name} 在地址 ${targetSymbol.address}`);
                sendEvent("function_found", {
                    message: `成功找到符号 ${targetSymbol.name}`,
                    address: targetSymbol.address.toString()
                });
                return targetSymbol.address;
            } else {
                console.log(`${DEBUG_PREFIX} 未找到匹配的符号: ${symbolName}`);
                sendEvent("error", {
                    message: `未找到匹配的符号: ${symbolName}`,
                    error_type: "symbol_not_found"
                });
                return null;
            }
        } catch (e) {
            console.log(`${DEBUG_PREFIX} 错误: 符号查找失败: ${e.message}`);
            sendEvent("error", {
                message: `符号查找失败: ${e.message}`,
                error_type: "symbol_lookup_error"
            });
            return null;
        }
    }

    // 安装 GIMP 的文件打开函数的 Hook
    function initFileOpenHook() {
        try {
            console.log(`${DEBUG_PREFIX} 开始查找 file_open_dialog_open_image 函数`);
            
            // 使用符号名称查找函数
            const fileOpenAddr = findFunctionAddress("file_open_dialog_open_image");
            
            if (!fileOpenAddr) {
                console.log(`${DEBUG_PREFIX} 错误: 未找到 file_open_dialog_open_image 函数`);
                sendEvent("error", {
                    message: "无法找到 file_open_dialog_open_image 函数",
                    error_type: "function_not_found"
                });
                return;
            }

            console.log(`${DEBUG_PREFIX} 成功找到 file_open_dialog_open_image 函数地址: ${fileOpenAddr}`);

            Interceptor.attach(fileOpenAddr, {
                onEnter: function (args) {
                    try {
                        console.log(`${DEBUG_PREFIX} 进入 file_open_dialog_open_image 函数`);
                        // 保存参数以便在 onLeave 中使用
                        this.dialog = args[0];
                        this.gimp = args[1];
                        this.file = args[2];
                        this.load_proc = args[3];
                        
                        console.log(`${DEBUG_PREFIX} 开始获取文件信息`);
                        // 获取文件名
                        var get_utf8_name = new NativeFunction(
                            Module.findExportByName(null, "gimp_file_get_utf8_name"),
                            'pointer',
                            ['pointer']
                        );
                        
                        var filename = get_utf8_name(this.file);
                        var filenameStr = filename ? Memory.readUtf8String(filename) : "unknown";
                        console.log(`${DEBUG_PREFIX} 文件名: ${filenameStr}`);
                        
                        // 获取文件路径
                        var get_path = new NativeFunction(
                            Module.findExportByName(null, "g_file_get_path"),
                            'pointer',
                            ['pointer']
                        );
                        
                        var path = get_path(this.file);
                        var pathStr = path ? Memory.readUtf8String(path) : "unknown";
                        console.log(`${DEBUG_PREFIX} 文件路径: ${pathStr}`);
                        
                        // 获取文件 URI
                        var get_uri = new NativeFunction(
                            Module.findExportByName(null, "g_file_get_uri"),
                            'pointer',
                            ['pointer']
                        );
                        
                        var uri = get_uri(this.file);
                        var uriStr = uri ? Memory.readUtf8String(uri) : "unknown";
                        console.log(`${DEBUG_PREFIX} 文件URI: ${uriStr}`);

                        sendEvent("file_open_called", {
                            message: `正在打开文件: ${filenameStr}`,
                            filename: filenameStr,
                            path: pathStr,
                            uri: uriStr
                        });
                    } catch (e) {
                        console.log(`${DEBUG_PREFIX} 错误: Hook onEnter 处理失败: ${e.message}`);
                        sendEvent("error", {
                            message: `Hook onEnter 处理失败: ${e.message}`,
                            error_type: "hook_execution_error"
                        });
                    }
                },

                onLeave: function (retval) {
                    try {
                        const success = retval.toInt32() !== 0;
                        console.log(`${DEBUG_PREFIX} 文件打开结果: ${success ? "成功" : "失败"}`);
                        sendEvent("file_open_returned", {
                            message: success ? "文件打开成功" : "文件打开失败",
                            success: success
                        });
                    } catch (e) {
                        console.log(`${DEBUG_PREFIX} 错误: Hook onLeave 处理失败: ${e.message}`);
                        sendEvent("error", {
                            message: `Hook onLeave 处理失败: ${e.message}`,
                            error_type: "hook_execution_error"
                        });
                    }
                }
            });
        } catch (e) {
            console.log(`${DEBUG_PREFIX} 错误: Hook 安装失败: ${e.message}`);
            sendEvent("error", {
                message: `Hook 安装失败: ${e.message}`,
                error_type: "hook_installation_error"
            });
        }
    }

    // 初始化 Hook 逻辑
    function initHook() {
        try {
            console.log(`${DEBUG_PREFIX} 开始初始化 Hook 脚本`);
            sendEvent("script_initialized", {
                message: "GIMP 文件打开函数 Hook 脚本已启动"
            });

            initFileOpenHook();

            console.log(`${DEBUG_PREFIX} Hook 脚本初始化完成`);
            sendEvent("hook_installed", {
                message: "文件打开 Hook 安装完成，等待操作..."
            });
        } catch (e) {
            console.log(`${DEBUG_PREFIX} 错误: Hook 初始化失败: ${e.message}`);
            sendEvent("error", {
                message: `Hook 初始化失败: ${e.message}`,
                error_type: "initialization_error"
            });
        }
    }

    // 执行脚本入口
    console.log(`${DEBUG_PREFIX} 开始执行 Hook 脚本`);
    initHook();

})(); 