// Blender搜索监控钩子脚本
// 用于监听Blender的搜索操作并检测特定查询
// 获取函数地址

(function() {
    // 全局变量
    const TARGET_NAME = "Ground";
    let searchFuncFound = false;
    let renameCorrect = false;
    let renameElement = false;
    
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
        // 查找 BKE_id_new_name_validate 函数在模块中的位置
        let BKE_id_new_name_validate = getFunctionAddress("_Z24BKE_id_new_name_validateR4MainR8ListBaseR2IDPKc13IDNewNameModeb");
        // 查找 BKE_object_dimensions_set_ex 函数在模块中的位置
        let BKE_object_dimensions_set_ex = getFunctionAddress("_Z28BKE_object_dimensions_set_exP6ObjectPKfiS2_PA4_S1_");


        // 如果没找到
        if (!BKE_id_new_name_validate) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到元素重命名函数"
            });
            return null;
        }

        if (!BKE_object_dimensions_set_ex) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到元素大小设置函数"
            });
            return null;
        }
                
        // 报告找到函数
        searchFuncFound = true;
        sendEvent("function_found", {
            address: BKE_id_new_name_validate.toString(),
            message: "找到元素重命名函数"
        });
        sendEvent("function_found", {
            address: BKE_object_dimensions_set_ex.toString(),
            message: "找到元素大小设置函数"
        });

        
        return [BKE_id_new_name_validate, BKE_object_dimensions_set_ex];
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
                    var newname = Memory.readUtf8String(args[3]);
                    if(newname.toLowerCase() == TARGET_NAME.toLowerCase()) 
                        renameCorrect = true;
                                       
                    sendEvent("rename_element_detected", {
                        name: newname,
                        message: `检测到重命名元素为: ${newname}`
                    });
                } catch (error) {
                    sendEvent("error", {
                        error_type: "general_error",
                        message: `执行错误: ${error.message}`
                    });
                }
            },
            onLeave: function(retval) {
                try {
                    if (renameCorrect) {
                        var action = retval.toInt32();
                        if(action != 0)
                            renameElement = true;
                        // 发送查询检测事件
                        sendEvent("rename_element_finished", {
                            success: action != 0,
                            message: `检测到执行重命名操作结束`
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

        // 安装搜索函数钩子
        Interceptor.attach(funcAddrs[1], {
            onEnter: function(args) {
                try {
                    if(renameElement) {
                        var value_ptr = args[1]; // 假设 value 是第 2 个参数（args[1]）
                        // 检查指针是否有效
                        if (!value_ptr.isNull()) {
                            // 读取 value 数组的值
                            var value_x = value_ptr.add(0).readFloat();
                            var value_y = value_ptr.add(4).readFloat();
                            var value_z = value_ptr.add(8).readFloat();
                            sendEvent("resize_element_detected", {
                                X: value_x,
                                Y: value_y,
                                Z: value_z,
                                message: `检测到设置元素大小为: ${value_x}, ${value_y}, ${value_z}`
                            });
                        }
                    }
                } catch (error) {
                    sendEvent("error", {
                        error_type: "general_error",
                        message: `执行错误: ${error.message}`
                    });
                }
            },
        });
        
        sendEvent("hook_installed", {
            message: "钩子安装完成，等待操作..."
        });
    }
    
    // 启动脚本
    initHook();
})();