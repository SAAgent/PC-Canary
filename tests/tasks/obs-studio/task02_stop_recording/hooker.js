// OBS录制更新监控钩子脚本
// 用于监听OBS的录制更新操作

(function () {
    // 脚本设置
    const FUNCTION_obs_output_stop = "obs_output_stop";
    const FUNCTION_obs_output_force_stop = "obs_output_force_stop";

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
    function initStopRecordingHook() {

        const obsOutputStopFuncAddr = getFunctionAddress(FUNCTION_obs_output_stop);
        if (!obsOutputStopFuncAddr) {
            return;
        }

        const obsOutputFroceStopFuncAddr = getFunctionAddress(FUNCTION_obs_output_force_stop);
        if (!obsOutputFroceStopFuncAddr) {
            return;
        }

        Interceptor.attach(obsOutputStopFuncAddr, {
            onEnter: function(args) {
                sendEvent("obs_output_stop_called", {
                    message: "拦截到结束录制的函数调用"
                });
            },

            onLeave: function(retval) {
                sendEvent("obs_output_stop_returned", {
                    message: "结束录制函数返回"
                });
            }
        });

        Interceptor.attach(obsOutputFroceStopFuncAddr, {
            onEnter: function(args) {
                sendEvent("obs_output_force_stop_called", {
                    message: "拦截到强制结束录制的函数调用"
                });
            },

            onLeave: function(retval) {
                sendEvent("obs_output_force_stop_returned", {
                    message: "强制结束录制函数返回"
                });
            }
        });
    }

    // 初始化钩子
    function initHook() {
        sendEvent("script_initialized", {
            message: "OBS结束录制的监控脚本已启动"
        });

        // 初始化各个钩子
        initStopRecordingHook();
        sendEvent("hook_installed", {
            message: "结束录制的监控钩子安装完成，等待操作..."
        });
    }

    // 启动脚本
    initHook();
})(); 