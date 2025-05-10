// 用于监听 GIMP 添加文字的函数调用

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

    // 查找文字工具相关函数地址
    function findTextToolFunctions() {
        try {
            console.log(`${DEBUG_PREFIX} 开始查找文字工具相关函数`);

            // 尝试不同的函数名变体
            const getTextAddr = findFunctionAddress("gimp_text_buffer_get_text") ||
                findFunctionAddress("_gimp_text_buffer_get_text") ||
                findFunctionAddress("gimp_text_buffer_get_text@plt");

            console.log(`${DEBUG_PREFIX} getText 函数地址: ${getTextAddr}`);

            if (!getTextAddr) {
                console.log(`${DEBUG_PREFIX} 错误: 未找到 getText 函数`);
                return null;
            }

            return {
                createLayer: findFunctionAddress("gimp_text_tool_create_layer"),
                getText: getTextAddr
            };
        } catch (e) {
            console.log(`${DEBUG_PREFIX} 错误: 查找函数失败: ${e.message}`);
            return null;
        }
    }

    // 添加调试函数
    function debugMemoryRead(address, size = 32) {
        try {
            console.log(`${DEBUG_PREFIX} 开始调试内存读取`);
            console.log(`${DEBUG_PREFIX} 地址: ${address}`);
            
            // 1. 读取原始字节
            const bytes = address.readByteArray(size);
            console.log(`${DEBUG_PREFIX} 原始字节: ${bytes}`);
            
            // 2. 尝试作为指针读取
            const ptr = address.readPointer();
            console.log(`${DEBUG_PREFIX} 作为指针: ${ptr}`);
            
            // 3. 尝试作为字符串读取
            try {
                const str = address.readUtf8String();
                console.log(`${DEBUG_PREFIX} 作为UTF8字符串: ${str}`);
            } catch (e) {
                console.log(`${DEBUG_PREFIX} 不是有效的UTF8字符串`);
            }
            
            // 4. 读取后续几个指针
            for (let i = 0; i < 3; i++) {
                const nextPtr = address.add(Process.pointerSize * i);
                const value = nextPtr.readPointer();
                console.log(`${DEBUG_PREFIX} 偏移 ${i} 的指针: ${value}`);
            }
            
        } catch (e) {
            console.log(`${DEBUG_PREFIX} 内存读取错误: ${e.message}`);
        }
    }

    // 安装文字工具函数的 Hook
    function initTextToolHook() {
        try {
            const functions = findTextToolFunctions();
            if (!functions) return;

            console.log(`${DEBUG_PREFIX} 成功找到文字工具函数地址`);

            // Hook gimp_text_tool_create_layer
            Interceptor.attach(functions.createLayer, {
                onEnter: function (args) {
                    try {
                        console.log(`${DEBUG_PREFIX} 进入 gimp_text_tool_create_layer 函数`);
                        this.textTool = args[0];
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
                        // 1. 检查 textTool 是否有效
                        if (!this.textTool) {
                            console.log(`${DEBUG_PREFIX} 错误: textTool 为空`);
                            return;
                        }
                        console.log(`${DEBUG_PREFIX} textTool 地址: ${this.textTool}`);
                        
                        // 2. 使用固定偏移量获取 buffer
                        const bufferOffset = 0x1d0; // 464字节
                        const bufferAddr = this.textTool.add(bufferOffset);
                        console.log(`${DEBUG_PREFIX} buffer 偏移量: ${bufferOffset}`);
                        console.log(`${DEBUG_PREFIX} buffer 地址: ${bufferAddr}`);
                        
                        // 3. 读取 buffer 指针
                        const buffer = bufferAddr.readPointer();
                        if (!buffer) {
                            console.log(`${DEBUG_PREFIX} 错误: buffer 指针为空`);
                            return;
                        }
                        console.log(`${DEBUG_PREFIX} buffer 指针值: ${buffer}`);
                        
                        // 4. 调用 getText 函数
                        const getTextFn = new NativeFunction(functions.getText, 'pointer', ['pointer']);
                        const textPtr = getTextFn(buffer);
                        console.log(`${DEBUG_PREFIX} getText 返回值: ${textPtr}`);
                        
                        if (!textPtr) {
                            console.log(`${DEBUG_PREFIX} 错误: getText 返回空指针`);
                            return;
                        }
                        
                        // 5. 读取文本内容
                        const text = textPtr.readUtf8String();
                        console.log(`${DEBUG_PREFIX} 文本内容: ${text}`);
                        
                        sendEvent("text_layer_created", {
                            message: "成功创建文字图层",
                            text_content: text,
                            buffer_address: buffer.toString(),
                            text_ptr: textPtr.toString()
                        });
                        
                    } catch (e) {
                        console.log(`${DEBUG_PREFIX} 错误: Hook onLeave 处理失败: ${e.message}`);
                        console.log(`${DEBUG_PREFIX} 错误堆栈: ${e.stack}`);
                        sendEvent("error", {
                            message: `Hook onLeave 处理失败: ${e.message}`,
                            error_type: "hook_execution_error",
                            stack: e.stack
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
                message: "GIMP 文字工具 Hook 脚本已启动"
            });

            initTextToolHook();

            console.log(`${DEBUG_PREFIX} Hook 脚本初始化完成`);
            sendEvent("hook_installed", {
                message: "文字工具 Hook 安装完成，等待操作..."
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