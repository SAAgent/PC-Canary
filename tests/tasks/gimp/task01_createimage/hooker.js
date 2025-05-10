// 用于监听 GIMP 创建新图像的函数调用

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
        console.log(`${DEBUG_PREFIX} 发送事件: ${eventType}`, JSON.stringify(payload));
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

    // 安装 GIMP 的图像创建函数的 Hook
    function initCreateImageHook() {
        // 尝试查找图像创建相关的函数
        const createImageAddr = findFunctionAddress("image_new_create_image");
        if (!createImageAddr) {
            sendEvent("error", {
                message: "无法获取创建图像函数的地址",
                error_type: "hook_installation_error"
            });
            return;
        }

        try {
        Interceptor.attach(createImageAddr, {
            onEnter: function (args) {
                    try {
                        console.log(`${DEBUG_PREFIX} 进入图像创建函数`);
                sendEvent("image_create_called", {
                            message: "调用图像创建函数",
                            function_name: "image_new_create_image"
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
                        console.log(`${DEBUG_PREFIX} 图像创建结果: ${success ? "成功" : "失败"}`);
                sendEvent("image_create_returned", {
                            message: success ? "图像创建成功" : "图像创建失败",
                            success: success,
                            return_value: retval.toInt32()
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

            console.log(`${DEBUG_PREFIX} 成功安装图像创建函数 Hook`);
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
            message: "GIMP 图像创建函数 Hook 脚本已启动"
        });

        initCreateImageHook();

            console.log(`${DEBUG_PREFIX} Hook 脚本初始化完成`);
        sendEvent("hook_installed", {
            message: "图像创建 Hook 安装完成，等待操作..."
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

