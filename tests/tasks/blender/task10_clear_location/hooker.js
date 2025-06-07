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
        // 查找 object_clear_loc 函数在模块中的位置
        let object_clear_loc = getFunctionAddress("_ZN7blender2ed6objectL16object_clear_locEP6Objectb");

        // 如果没找到
        if (!object_clear_loc) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到清除元素位置函数"
            });
            return null;
        }
                
        // 报告找到函数
        searchFuncFound = true;
        sendEvent("function_found", {
            address: object_clear_loc.toString(),
            message: "找到清除元素位置函数"
        });

        
        return [object_clear_loc];
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
            onLeave: function() {
                try {
                    // 发送查询检测事件
                    sendEvent("clear_element_detected", {
                        leave: true,
                        message: `检测到成功执行清除元素位置操作`
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