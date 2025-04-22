// OBS切换场景钩子脚本
// 用于监听OBS的切换场景操作

(function () {
    // 脚本设置
    const FUNCTION_SetCurrentScene = "_ZN8OBSBasic15SetCurrentSceneE10OBSSafeRefIP10obs_sourceXadL_Z18obs_source_get_refEEXadL_Z18obs_source_releaseEEEb";

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

    // 初始化录制更新钩子
    function initSetCurrentSceneHook() {

        const SetCurrentSceneFuncAddr = getFunctionAddress(FUNCTION_SetCurrentScene);
        if (!SetCurrentSceneFuncAddr) {
            return;
        }

        Interceptor.attach(SetCurrentSceneFuncAddr, {
            onEnter: function(args) {
                sendEvent("setCurrentScene_called", {
                    message: "拦截到切换当前场景的函数调用"
                });
                const scene = new NativePointer(args[1]);
                console.log("scene pointer: ", scene);
                const scene_val = scene.readPointer();
                console.log("scene_val pointer: ", scene_val);
                const name_pointer = scene_val.readPointer();
                console.log("name pointer: ", name_pointer);
                const name = name_pointer.readCString(-1);
                console.log("name: ", name);
                this.name = name;
                this.force = args[2];
            },

            onLeave: function(retval) {
                sendEvent("setCurrentScene_returned", {
                    message: "切换当前场景函数返回"
                });
                console.log("this.name: ", this.name);
                console.log("this.force: ", this.force);
                sendEvent("current_scene", {
                    scene: this.name,
                    message: `当前场景名称: ${this.name}`
                })
            }
        });
    }

    // 初始化钩子
    function initHook() {
        sendEvent("script_initialized", {
            message: "OBS切换场景的监控脚本已启动"
        });

        // 初始化各个钩子
        initSetCurrentSceneHook();
        sendEvent("hook_installed", {
            message: "切换场景的监控钩子安装完成，等待操作..."
        });
    }

    // 启动脚本
    initHook();
})(); 