// 用于监听 GIMP 水平翻转图像的函数调用

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

    // 安装图像翻转函数的 Hook
    function initFlipHook() {
        try {
            console.log(`${DEBUG_PREFIX} 开始查找 gimp_image_flip 函数`);
            
            // 使用自定义函数查找地址
            const flipAddr = findFunctionAddress("gimp_image_flip");
            
            if (!flipAddr) {
                console.log(`${DEBUG_PREFIX} 错误: 未找到 gimp_image_flip 函数`);
                sendEvent("error", {
                    message: "无法找到 gimp_image_flip 函数",
                    error_type: "function_not_found"
                });
                return;
            }

            console.log(`${DEBUG_PREFIX} 成功找到 gimp_image_flip 函数地址: ${flipAddr}`);

            // Hook gimp_image_flip 函数
            Interceptor.attach(flipAddr, {
                onEnter: function (args) {
                    try {
                        const flip_type = args[2].toInt32();
                        
                        // 将翻转类型转换为可读字符串
                        const flip_str = (flip_type === 0) ? "水平" : (flip_type === 1) ? "垂直" : "自动";
                        
                        console.log(`${DEBUG_PREFIX} 调用 gimp_image_flip: 类型=${flip_str}`);
                        
                        // 发送事件
                        sendEvent("image_flipped", {
                            message: `图像被${flip_str}翻转`,
                            flip_type: flip_type
                        });
                        
                    } catch (e) {
                        console.log(`${DEBUG_PREFIX} 错误: Hook onEnter 处理失败: ${e.message}`);
                        sendEvent("error", {
                            message: `Hook onEnter 处理失败: ${e.message}`,
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
                message: "GIMP 图像翻转 Hook 脚本已启动"
            });

            initFlipHook();

            console.log(`${DEBUG_PREFIX} Hook 脚本初始化完成`);
            sendEvent("hook_installed", {
                message: "图像翻转 Hook 安装完成，等待操作..."
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