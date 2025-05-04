(function () {
    // 相关符号
    const FUNC_CREATE = "obs_source_create";
    const FUNC_REMOVE = "obs_source_remove";
    const FUNC_SET_ORDER = "obs_sceneitem_set_order";
    const FUNC_SAVE = "OBSBasic::Save";
    const FUNC_SAVE_SYMBOL = "_ZN8OBSBasic4SaveEPKc";

    const EVENT_ON_ENTER = "function called";
    const EVENT_ON_LEAVE = "function returned";
    const EVENT_ON_SUCCESS = "scene_json_path";
    const PAYLOAD_SUCCESS = "path";

    const MESSAGE_SCRIPT_INITIALIZED = "监控脚本已启动";
    const MESSAGE_HOOK_INSTALLED = "监控钩子安装完成，等待操作...";
    const MESSAGE_ON_SUCCESS = "批量管理纯色源操作完成";

    // 记录操作
    let addCount = 0, removeCount = 0, reorderCount = 0;
    let lastScenePath = null;

    function sendEvent(eventType, data = {}) {
        const payload = {
            event: eventType,
            ...data,
            timestamp: new Date().getTime()
        };
        send(payload);
    }

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

    // 钩子：添加纯色源
    function hookCreate() {
        const addr = getFunctionAddress(FUNC_CREATE);
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter(args) {
                const name = args[1].readUtf8String();
                const type = args[0].readUtf8String();
                if (type === "color_source") {
                    addCount++;
                    sendEvent(EVENT_ON_ENTER, { function: FUNC_CREATE, name });
                }
            },
            onLeave(retval) {
                sendEvent(EVENT_ON_LEAVE, { function: FUNC_CREATE });
            }
        });
    }

    // 钩子：删除纯色源
    function hookRemove() {
        const addr = getFunctionAddress(FUNC_REMOVE);
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter(args) {
                removeCount++;
                sendEvent(EVENT_ON_ENTER, { function: FUNC_REMOVE });
            },
            onLeave(retval) {
                sendEvent(EVENT_ON_LEAVE, { function: FUNC_REMOVE });
            }
        });
    }

    // 钩子：重排sceneitem
    function hookSetOrder() {
        const addr = getFunctionAddress(FUNC_SET_ORDER);
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter(args) {
                reorderCount++;
                sendEvent(EVENT_ON_ENTER, { function: FUNC_SET_ORDER });
            },
            onLeave(retval) {
                sendEvent(EVENT_ON_LEAVE, { function: FUNC_SET_ORDER });
            }
        });
    }

    // 钩子：保存场景，获取json路径
    function hookSave() {
        const addr = getFunctionAddress(FUNC_SAVE_SYMBOL);
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter(args) {
                this.file = args[1].readCString(-1);
                sendEvent(EVENT_ON_ENTER, { function: FUNC_SAVE });
            },
            onLeave(retval) {
                lastScenePath = this.file;
                sendEvent(EVENT_ON_LEAVE, { function: FUNC_SAVE });
                if (lastScenePath && lastScenePath.endsWith(".json")) {
                    sendEvent(EVENT_ON_SUCCESS, {
                        message: MESSAGE_ON_SUCCESS,
                        [PAYLOAD_SUCCESS]: lastScenePath
                    });
                }
            }
        });
    }

    function initHook() {
        sendEvent("script_initialized", { message: MESSAGE_SCRIPT_INITIALIZED });
        hookCreate();
        hookRemove();
        hookSetOrder();
        hookSave();
        sendEvent("hook_installed", { message: MESSAGE_HOOK_INSTALLED });
    }

    initHook();
})(); 