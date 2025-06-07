// Blender搜索监控钩子脚本
// 用于监听Blender的搜索操作并检测特定查询
// 获取函数地址

(function() {
    // 全局变量
    let searchFuncFound = false;
    
    // 向评估系统发送事件
    function sendEvent(eventType, data = {}) {
        const payload = {
            event: eventType,
            ...data,
            timestamp: new Date().getTime()
        };
        send(payload);
    }
    
    // 查找Widget::search函数
    function findSearchFunction() {
        // 查找 wm_window_new 函数在模块中的位置
        let wm_window_new = getFunctionAddress("_Z13wm_window_newPK4MainP15wmWindowManagerP8wmWindowb");

        // 如果没找到
        if (!wm_window_new) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到新建窗口函数"
            });
            return null;
        }
                
        // 报告找到函数
        searchFuncFound = true;
        sendEvent("function_found", {
            address: wm_window_new.toString(),
            message: "找到新建窗口函数"
        });
        
        return [wm_window_new];
    }
    
    function getFunctionAddress(functionName) {
        const funcAddr = DebugSymbol.getFunctionByName(functionName);
        if (!funcAddr) {
            console.error(`无法找到函数 ${functionName}`);
            // 发送错误事件
            return null;
        }
    
        let address = funcAddr.toString();
        console.log(`找到函数 ${functionName} 的实际地址: ${funcAddr}`);
        // 发送成功事件
        return funcAddr;
    }
    
    // 初始化钩子
    function initHook() {
        sendEvent("script_initialized", {
            message: "Blender搜索监控脚本已启动"
        });
        
        // 查找搜索函数
        const funcAddrs = findSearchFunction();
        if (!searchFuncFound) {
            return;
        }
        
        
        // 安装搜索函数钩子
        Interceptor.attach(funcAddrs[0], {
            onLeave: function(retval) {
                try {
                    sendEvent("new_window_detected", {
                        retval: retval.isNull() ? 0 : 1,
                        message: `检测到新建窗口函数结束`
                    });
                } catch (error) {
                    sendEvent("error", {
                        error_type: "general_error",
                        message: `执行错误: ${error.message}`
                    });
                }
            }
        });
        
        sendEvent("hook_installed", {
            message: "钩子安装完成，等待操作..."
        });
    }
    
    // 启动脚本
    initHook();
})();