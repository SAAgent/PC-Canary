// Blender搜索监控钩子脚本
// 用于监听Blender的搜索操作并检测特定查询
// 获取函数地址

(function() {
    const TARGET_ADD1 = "Cone";
    const TARGET_ADD2 = "Cylinder";
    const TARGET_RET = 4;
    const TARGET_LOCATION = [0,0,2];
    // 全局变量
    let searchFuncFound = false;
    let addElementCount = 0;
    let preAddedElement = "";
    let selectAllElement = false;
    let setLocation = false;
    
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
        // 查找 BKE_object_to_mat4 函数在模块中的位置
        let BKE_object_to_mat4 = getFunctionAddress("_Z18BKE_object_to_mat4PK6ObjectPA4_f");
        // 查找 object_select_all_exec 函数在模块中的位置
        let object_select_all_exec = getFunctionAddress("_ZN7blender2ed6objectL22object_select_all_execEP8bContextP10wmOperator");
        // 查找 ED_mesh_join_objects_exec` 函数在模块中的位置
        let ED_mesh_join_objects_exec = getFunctionAddress("_Z25ED_mesh_join_objects_execP8bContextP10wmOperator");


        // 如果没找到
        if (!BKE_mesh_add) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到增加元素函数"
            });
            return null;
        }
        if (!BKE_object_to_mat4) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到物体位置更改函数"
            });
            return null;
        }

        if (!object_select_all_exec) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到切换局部视图函数"
            });
            return null;
        }

        if (!ED_mesh_join_objects_exec) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到合并元素函数"
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
            address: BKE_object_to_mat4.toString(),
            message: "找到物体位置更改函数"
        });

        sendEvent("function_found", {
            address: object_select_all_exec.toString(),
            message: "找到全选元素函数"
        });

        sendEvent("function_found", {
            address: ED_mesh_join_objects_exec.toString(),
            message: "找到合并元素函数"
        });

        
        return [BKE_mesh_add,BKE_object_to_mat4, object_select_all_exec, ED_mesh_join_objects_exec];
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
    function compareArrays(arr1, arr2) {
        if (arr1.length != arr2.length) {
            return false;
        }
        for (let i = 0; i < arr1.length; i++) {
            if (arr1[i] != arr2[i]) {
                return false;
            }
        }
        return true;
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
                    
                    if (nameStr.toLowerCase() == TARGET_ADD1.toLowerCase() || nameStr.toLowerCase() == TARGET_ADD2.toLowerCase()) {
                        if (nameStr.toLowerCase() != preAddedElement.toLowerCase()){
                            preAddedElement = nameStr;
                            if(addElementCount == 0) {
                                // 发送查询检测事件
                                sendEvent("add_first_element_detected", {
                                    name: nameStr,
                                    message: `检测到新增第一个元素: ${nameStr}`
                                });
                            }
                            else if(addElementCount == 1) {
                                // 发送查询检测事件
                                sendEvent("add_second_element_detected", {
                                    name: nameStr,
                                    message: `检测到新增第二个元素: ${nameStr}`
                                });
                            }
                        }
                        else{
                            addElementCount--;
                            sendEvent("add_frist_element_detected", {
                                name: nameStr,
                                message: `检测到重复新增元素: ${nameStr}`
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
            onLeave: function(retval) {
                try {                    
                    if (!retval.isNull()) 
                        addElementCount++;
                    if(addElementCount == 1){
                        // 发送查询检测事件
                        sendEvent("add_first_element_finished", {
                            success: !retval.isNull(),
                            message: `检测到新增第一个元素结束`
                        });
                    }
                    else if(addElementCount == 2){
                        // 发送查询检测事件
                        sendEvent("add_second_element_finished", {
                            success: !retval.isNull(),
                            message: `检测到新增第二个元素结束`
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

        Interceptor.attach(funcAddrs[1], {
            onEnter: function(args) {
                try {
                    if(addElementCount == 2) {
                        var namePtr = args[0].add(0x2a);
                        var locPtr = args[0].add(0x248);
                        var dlocPtr = args[0].add(0x254);
                        var name = namePtr.readUtf8String();
                        var location = [];
                        for(var i = 0; i < 3; i++) {
                            var loc = parseInt(locPtr.add(i * 4).readFloat(),10);
                            loc += parseInt(dlocPtr.add(i * 4).readFloat(),10);
                            location.push(loc);
                        }

                        if (name.toLowerCase() == TARGET_ADD1.toLowerCase() && compareArrays(location,TARGET_LOCATION)) {
                            setLocation = true;
                            // 发送查询检测事件
                            sendEvent("set_location_detected", {
                                location: location,
                                message: `检测到物体位置更改`
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

        Interceptor.attach(funcAddrs[2], {
            onLeave: function(retval) {
                try {
                    if (setLocation) {
                        if (retval.toInt32() == TARGET_RET) 
                            selectAllElement = true;
                        // 发送查询检测事件
                        sendEvent("select_all_detected", {
                            success: retval.toInt32() == TARGET_RET,
                            message: `选择全部物体结束`
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

        Interceptor.attach(funcAddrs[3], {
            onLeave: function(retval) {
                try {
                    if (selectAllElement) {
                        // 发送查询检测事件
                        sendEvent("join_element_detected", {
                            success: retval.toInt32() == TARGET_RET,
                            message: `合并已选物体结束`
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