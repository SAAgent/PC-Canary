// Blender搜索监控钩子脚本
// 用于监听Blender的搜索操作并检测特定查询
// 获取函数地址

(function() {
    const TARGET_ADD = "Cone";
    // 全局变量
    let searchFuncFound = false;
    let addElement = false;
    
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
        // 查找 BKE_mesh_add 函数在模块中的位置
        let BKE_mesh_add = getFunctionAddress("_Z12BKE_mesh_addP4MainPKc");
        // 查找 BKE_mesh_center_of_surface 函数在模块中的位置
        let BKE_mesh_center_of_surface = getFunctionAddress("_Z26BKE_mesh_center_of_surfacePK4MeshPf");

        // 如果没找到
        if (!BKE_mesh_add) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到增加元素函数"
            });
            return null;
        }

        if (!BKE_mesh_center_of_surface) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到原点设置函数"
            });
            return null;
        }
                
        // 报告找到函数
        searchFuncFound = true;
        sendEvent("function_found", {
            address: BKE_mesh_add.toString(),
            message: "找到增加元素函数"
        });

        sendEvent("function_found", {
            address: BKE_mesh_center_of_surface.toString(),
            message: "找到原点设置函数"
        });

        
        return [BKE_mesh_add, BKE_mesh_center_of_surface];
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
                    var namePtr = args[1];
                    var nameStr = Memory.readUtf8String(namePtr);
                    
                    if (nameStr.toLowerCase() == TARGET_ADD.toLowerCase()) {
                        // 发送查询检测事件
                        sendEvent("add_element_detected", {
                            name: nameStr,
                            message: `检测到新增元素: ${nameStr}`
                        });
                    }
                } catch (error) {
                    sendEvent("error", {
                        error_type: "general_error",
                        message: `执行错误: ${error.message}`
                    });
                }
            },
            onLeave: function(retval) {
                try {                    
                    if (!retval.isNull()) 
                        addElement = true;

                    sendEvent("add_element_finished", {
                        success: !retval.isNull(),
                        message: `检测到新增元素结束`
                    });
                } catch (error) {
                    sendEvent("error", {
                        error_type: "general_error",
                        message: `执行错误: ${error.message}`
                    });
                }
            }
        });

        Interceptor.attach(funcAddrs[1], {
            onLeave: function(retval) {
                try {
                    if (addElement) {
                        sendEvent("set_origin_detected", {
                            success: retval.toInt32() == 1,
                            message: `设置原点位置结束`
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