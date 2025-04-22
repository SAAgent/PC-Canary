// OBS录制更新监控钩子脚本
// 用于监听OBS的录制更新操作

(function () {
    // 脚本设置
    const FUNCTION_NAME_StartRecording = "_ZN12SimpleOutput14StartRecordingEv";

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
    function initStartRecordingHook() {
        const startRecrodingFuncAddr = getFunctionAddress(FUNCTION_NAME_StartRecording);
        if (!startRecrodingFuncAddr) {
            return;
        }

        Interceptor.attach(startRecrodingFuncAddr, {
            onEnter: function(args) {
                sendEvent("start_recording_called", {
                    message: "拦截到录制更新函数调用"
                });
            },

            onLeave: function(retval) {
                sendEvent("start_recording_returned", {
                    message: "录制更新函数返回"
                });
                
                sendEvent("is_recording", {
                    recording: retval,
                    message: `当前录制状态: ${retval}`
                });
            }
        });
    }

    // 初始化钩子
    function initHook() {
        sendEvent("script_initialized", {
            message: "OBS录制更新监控脚本已启动"
        });

        // 初始化各个钩子
        initStartRecordingHook();
        sendEvent("hook_installed", {
            message: "录制更新监控钩子安装完成，等待操作..."
        });
    }

    // 启动脚本
    initHook();
})(); 