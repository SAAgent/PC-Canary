// Blender搜索监控钩子脚本
// 用于监听Blender的搜索操作并检测特定查询
// 获取函数地址

(function() {
    const TARGET_SCALE = [2,1,1];
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
        // 查找 size_to_mat3 函数在模块中的位置
        let size_to_mat3 = getFunctionAddress("_Z12size_to_mat3PA3_fPKf");

        if (!size_to_mat3) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到缩放元素函数"
            });
            return null;
        }
                
        // 报告找到函数
        searchFuncFound = true;
        sendEvent("function_found", {
            address: size_to_mat3.toString(),
            message: "找到缩放元素函数"
        });

        
        return [size_to_mat3];
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
            onEnter: function(args) {
                try {
                    var sizePtr = args[1];
                    var x = Memory.readFloat(sizePtr.add(0));
                    var y = Memory.readFloat(sizePtr.add(4));
                    var z = Memory.readFloat(sizePtr.add(8));
                    
                    if (x == TARGET_SCALE[0] && y == TARGET_SCALE[1] && z == TARGET_SCALE[2]) {
                        // 发送查询检测事件
                        sendEvent("scale_element_detected", {
                            scale: [x, y, z],
                            message: `检测到缩放元素: ${x} ${y} ${z}`
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