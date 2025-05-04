(function () {
    // 脚本设置
    const MESSAGE_script_initialized = "监控脚本已启动";
    const MESSAGE_hook_installed = "监控钩子安装完成，等待操作...";
    const MESSAGE_filter_created = "捕获到滤镜创建事件";
    const MESSAGE_filter_enabled = "捕获到滤镜启用事件";
    const MESSAGE_filter_disabled = "捕获到滤镜禁用事件";
    const MESSAGE_filter_removed = "捕获到滤镜移除事件";

    // 向评估系统发送事件
    function sendEvent(eventType, data = {}) {
        const payload = {
            event: eventType,
            ...data,
            timestamp: new Date().getTime()
        };
        send(payload);
    }

    // 获取函数地址
    function getFunctionAddress(functionName) {
        const funcAddr = DebugSymbol.getFunctionByName(functionName);
        if (!funcAddr) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: `无法找到函数 ${functionName}`
            });
            return null;
        }

        sendEvent("function_found", {
            address: funcAddr.toString(),
            message: `找到函数 ${functionName} 的实际地址`
        });
        return funcAddr;
    }

    // 创建钩子函数
    function hookFilterCreate() {
        // 函数：obs_source_filter_add，用于添加滤镜
        let symbol_name = "obs_source_filter_add";

        Interceptor.attach(getFunctionAddress(symbol_name), {
            onEnter(args) {
                this.source = args[0];
                this.filter = args[1];
                
                // 获取源和滤镜名称
                if (this.source && this.filter) {
                    try {
                        // 调用obs_source_get_name获取源名称
                        const obs_source_get_name = DebugSymbol.getFunctionByName("obs_source_get_name");
                        const sourceName = new NativeFunction(obs_source_get_name, "pointer", ["pointer"])(this.source).readUtf8String();
                        const filterName = new NativeFunction(obs_source_get_name, "pointer", ["pointer"])(this.filter).readUtf8String();
                        
                        // 调用obs_source_get_unversioned_id获取滤镜类型
                        const obs_source_get_id = DebugSymbol.getFunctionByName("obs_source_get_unversioned_id");
                        const filterId = new NativeFunction(obs_source_get_id, "pointer", ["pointer"])(this.filter).readUtf8String();

                        sendEvent("filter_created", {
                            message: MESSAGE_filter_created,
                            sourceName: sourceName,
                            filterName: filterName,
                            filterKind: filterId
                        });
                    } catch (e) {
                        sendEvent("error", {
                            error_type: "get_source_info_error",
                            message: `获取源信息时出错: ${e.toString()}`
                        });
                    }
                }
            }
        });
    }

    // 钩子：滤镜启用/禁用
    function hookFilterEnable() {
        // 函数：obs_source_set_enabled，用于启用或禁用滤镜
        let symbol_name = "obs_source_set_enabled";

        Interceptor.attach(getFunctionAddress(symbol_name), {
            onEnter(args) {
                this.source = args[0];
                this.enabled = args[1].toInt32(); // 布尔值参数，1为启用，0为禁用
                
                // 检查是否为滤镜
                if (this.source) {
                    try {
                        // 检查是否是过滤器
                        const obs_source_get_type = DebugSymbol.getFunctionByName("obs_source_get_type");
                        const sourceType = new NativeFunction(obs_source_get_type, "int", ["pointer"])(this.source);
                        
                        // OBS_SOURCE_TYPE_FILTER = 1
                        if (sourceType === 1) {
                            // 获取滤镜名称
                            const obs_source_get_name = DebugSymbol.getFunctionByName("obs_source_get_name");
                            const filterName = new NativeFunction(obs_source_get_name, "pointer", ["pointer"])(this.source).readUtf8String();
                            
                            // 获取所属的源
                            const obs_filter_get_parent = DebugSymbol.getFunctionByName("obs_filter_get_parent");
                            const parent = new NativeFunction(obs_filter_get_parent, "pointer", ["pointer"])(this.source);
                            
                            let sourceName = "unknown";
                            if (parent) {
                                sourceName = new NativeFunction(obs_source_get_name, "pointer", ["pointer"])(parent).readUtf8String();
                            }
                            
                            if (this.enabled === 1) {
                                sendEvent("filter_enabled", {
                                    message: MESSAGE_filter_enabled,
                                    sourceName: sourceName,
                                    filterName: filterName
                                });
                            } else {
                                sendEvent("filter_disabled", {
                                    message: MESSAGE_filter_disabled,
                                    sourceName: sourceName,
                                    filterName: filterName
                                });
                            }
                        }
                    } catch (e) {
                        sendEvent("error", {
                            error_type: "get_filter_enable_info_error",
                            message: `获取滤镜启用信息时出错: ${e.toString()}`
                        });
                    }
                }
            }
        });
    }

    // 钩子：滤镜移除
    function hookFilterRemove() {
        // 函数：obs_source_filter_remove，用于移除滤镜
        let symbol_name = "obs_source_filter_remove";

        Interceptor.attach(getFunctionAddress(symbol_name), {
            onEnter(args) {
                this.source = args[0];
                this.filter = args[1];
                
                // 获取源和滤镜名称
                if (this.source && this.filter) {
                    try {
                        // 调用obs_source_get_name获取源名称
                        const obs_source_get_name = DebugSymbol.getFunctionByName("obs_source_get_name");
                        const sourceName = new NativeFunction(obs_source_get_name, "pointer", ["pointer"])(this.source).readUtf8String();
                        const filterName = new NativeFunction(obs_source_get_name, "pointer", ["pointer"])(this.filter).readUtf8String();

                        sendEvent("filter_removed", {
                            message: MESSAGE_filter_removed,
                            sourceName: sourceName,
                            filterName: filterName
                        });
                    } catch (e) {
                        sendEvent("error", {
                            error_type: "get_source_info_error",
                            message: `获取源信息时出错: ${e.toString()}`
                        });
                    }
                }
            }
        });
    }

    // 初始化钩子
    function initHook() {
        sendEvent("script_initialized", {
            message: MESSAGE_script_initialized
        });

        // 初始化各个钩子
        hookFilterCreate();
        hookFilterEnable(); 
        hookFilterRemove();

        sendEvent("hook_installed", {
            message: MESSAGE_hook_installed
        });
    }

    // 启动脚本
    initHook();
})();