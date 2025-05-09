(function () {
    // 脚本设置
    const EVENT_ON_ENTER = "function called";
    const EVENT_ON_LEAVE = "function returned";
    
    const MESSAGE_source_deleted = "源已被删除";
    const MESSAGE_script_initialized = "监控脚本已启动";
    const MESSAGE_hook_installed = "监控钩子安装完成，等待操作...";

    // 向评估系统发送事件
    function sendEvent(eventType, data = {}) {
        console.log("[Event]", eventType, JSON.stringify(data, null, 2));
        const payload = {
            event: eventType,
            ...data,
            timestamp: new Date().getTime()
        };
        send(payload);
    }

    // 获取函数地址
    function getFunctionAddress(functionName) {
        console.log("[Debug] 正在查找函数:", functionName);
        const funcAddr = DebugSymbol.getFunctionByName(functionName);
        if (!funcAddr) {
            console.log("[Error] 未找到函数:", functionName);
            sendEvent("error", {
                error_type: "function_not_found",
                message: `无法找到函数 ${functionName}`
            });
            return null;
        }

        console.log("[Debug] 找到函数地址:", functionName, funcAddr);
        sendEvent("function_found", {
            address: funcAddr.toString(),
            message: `找到函数 ${functionName} 的实际地址`
        });
        return funcAddr;
    }

    // 获取场景项目的源
    function obs_sceneitem_get_source(item) {
        const func = new NativeFunction(
            getFunctionAddress("obs_sceneitem_get_source"),
            'pointer',
            ['pointer']
        );
        return func(item);
    }

    // 监控场景项目的删除
    function hookSceneItemRemove() {
        console.log("[Hook] 开始设置obs_sceneitem_remove钩子");
        const funcAddr = getFunctionAddress("obs_sceneitem_remove");
        if (!funcAddr) return;

        Interceptor.attach(funcAddr, {
            onEnter(args) {
                this.item = args[0];
                if (this.item) {
                    try {
                        const source = new OBSSource(obs_sceneitem_get_source(this.item));
                        const source_name = source.getName();
                        const source_id = source.getId();
                        
                        console.log("[obs_sceneitem_remove] 源名称:", source_name);
                        console.log("[obs_sceneitem_remove] 源类型:", source_id);
                        
                        // 只关注颜色源
                        if (source_id === "color_source_v3") {
                            sendEvent("source_deleted", {
                                source_name: source_name,
                                source_id: source_id,
                                message: MESSAGE_source_deleted
                            });
                        }
                    } catch (error) {
                        console.log("[Error] 获取源信息失败:", error);
                    }
                }
            }
        });
    }

    function hookSourceRemove() {
        console.log("[Hook] 开始设置obs_source_remove钩子");
        const funcAddr = getFunctionAddress("obs_source_remove");
        if (!funcAddr) return;

        Interceptor.attach(funcAddr, {
            onEnter(args) {
                this.source = args[0];
                if (this.source) {
                    try {
                        const source = new OBSSource(this.source);
                        const source_name = source.getName();
                        const source_id = source.getId();
                        
                        console.log("[obs_source_remove] 源名称:", source_name);
                        console.log("[obs_source_remove] 源类型:", source_id);
                        
                        // 只关注颜色源
                        if (source_id === "color_source_v3") {
                            sendEvent("source_deleted", {
                                source_name: source_name,
                                source_id: source_id,
                                message: MESSAGE_source_deleted
                            });
                        }
                    } catch (error) {
                        console.log("[Error] 获取源信息失败:", error);
                    }
                }
            }
        });
    }

    // OBSSource类用于操作OBS的源
    class OBSSource {
        constructor(ptr) {
            console.log("[OBSSource] 创建新实例，指针:", ptr);
            this.ptr = ptr;
        }
        
        getName() {
            console.log("[OBSSource] 获取源名称");
            const func = new NativeFunction(
                getFunctionAddress("obs_source_get_name"),
                'pointer',
                ['pointer']
            );
            const namePtr = func(this.ptr);
            const name = namePtr.readCString(-1);
            console.log("[OBSSource] 获取到的源名称:", name);
            return name;
        }

        getId() {
            console.log("[OBSSource] 获取源ID");
            const func = new NativeFunction(
                getFunctionAddress("obs_source_get_id"),
                'pointer',
                ['pointer']
            );
            const idPtr = func(this.ptr);
            const id = idPtr.readCString(-1);
            console.log("[OBSSource] 获取到的源ID:", id);
            return id;
        }
    }

    // 初始化钩子
    function initHook() {
        console.log("[Init] 开始初始化钩子");
        sendEvent("script_initialized", {
            message: MESSAGE_script_initialized
        });

        // 初始化各个钩子
        hookSceneItemRemove();
        hookSourceRemove();
        
        console.log("[Init] 钩子初始化完成");
        sendEvent("hook_installed", {
            message: MESSAGE_hook_installed
        });
    }

    // 启动脚本
    console.log("[Start] 脚本开始执行");
    initHook();
    console.log("[Start] 脚本执行完成，等待事件...");
})(); 