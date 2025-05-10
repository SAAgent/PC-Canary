// 用于监听 GIMP 旋转图片的函数调用

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

    // 安装 GIMP 的图片旋转函数的 Hook
    function initRotateHook() {
        try {
            console.log(`${DEBUG_PREFIX} 开始查找 gimp_image_rotate 函数`);
            
            // 使用符号名称查找函数
            const rotateAddr = findFunctionAddress("gimp_image_rotate");
            
            if (!rotateAddr) {
                console.log(`${DEBUG_PREFIX} 错误: 未找到 gimp_image_rotate 函数`);
                sendEvent("error", {
                    message: "无法找到 gimp_image_rotate 函数",
                    error_type: "function_not_found"
                });
                return;
            }

            console.log(`${DEBUG_PREFIX} 成功找到 gimp_image_rotate 函数地址: ${rotateAddr}`);

            Interceptor.attach(rotateAddr, {
                onEnter: function (args) {
                    try {
                        console.log(`${DEBUG_PREFIX} 进入 gimp_image_rotate 函数`);
                        sendEvent("rotate_called", {
                            message: "正在旋转图像"
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
                        console.log(`${DEBUG_PREFIX} 图像旋转结果: ${success ? "成功" : "失败"}`);
                        sendEvent("rotate_returned", {
                            message: success ? "图像旋转成功" : "图像旋转失败",
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
                message: "GIMP 图像旋转函数 Hook 脚本已启动"
            });

            initRotateHook();

            console.log(`${DEBUG_PREFIX} Hook 脚本初始化完成`);
            sendEvent("hook_installed", {
                message: "图像旋转 Hook 安装完成，等待操作..."
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