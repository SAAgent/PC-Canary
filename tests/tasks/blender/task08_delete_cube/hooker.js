// Blender搜索监控钩子脚本
// 用于监听Blender的搜索操作并检测特定查询
// 获取函数地址

(function() {
    // 全局变量
    const TARGET_DELETE = 1;
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
        // 查找 BKE_id_multi_tagged_delete 函数在模块中的位置
        let BKE_id_multi_tagged_delete = getFunctionAddress("_Z26BKE_id_multi_tagged_deleteP4Main");

        // 如果没找到
        if (!BKE_id_multi_tagged_delete) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到元素删除函数"
            });
            return null;
        }
                
        // 报告找到函数
        searchFuncFound = true;
        sendEvent("function_found", {
            address: BKE_id_multi_tagged_delete.toString(),
            message: "找到元素删除函数"
        });

        
        return [BKE_id_multi_tagged_delete];
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
                    var returnValue = retval.toInt32();
                    if (returnValue == TARGET_DELETE) {
                        // 发送查询检测事件
                        sendEvent("delete_element_detected", {
                            retval: returnValue,
                            message: `检测到成功执行删除元素操作`
                        });
                    }                    
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