// Blender搜索监控钩子脚本
// 用于监听Blender的搜索操作并检测特定查询
// 获取函数地址

(function() {
    const TARGET_FILE_PATH = "/home/agent/blender-git/metaball_cube_copy.blend";
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
        // 查找 BLO_write_file 函数在模块中的位置
        let BLO_write_file = getFunctionAddress("_Z14BLO_write_fileP4MainPKciPK20BlendFileWriteParamsP10ReportList");

        // 如果没找到
        if (!BLO_write_file) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到另存文件函数"
            });
            return null;
        }
                
        // 报告找到函数
        searchFuncFound = true;
        sendEvent("function_found", {
            address: BLO_write_file.toString(),
            message: "找到另存文件函数"
        });
        
        return [BLO_write_file];
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
                    var BLO_write_file_params_ptr = args[1];
                    var filepath_ptr = ptr(BLO_write_file_params_ptr).add(0);  // filepath 在结构体中的偏移量为 0
                    var filepath = Memory.readUtf8String(filepath_ptr);  

                    if (filepath == TARGET_FILE_PATH) {
                        // 发送事件
                        sendEvent("saveas_file_detected", {
                            file_path: filepath,
                            message: `检测到另存文件到: ${filepath}`
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
                    // 获取函数的返回值（假设返回值是一个 32 位整数）
                    var returnValue = retval.toInt32();

                    if (returnValue != 0) {
                        sendEvent("saveas_file_finished", {
                            retval: true,
                            message: `检测到另存文件结束`
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