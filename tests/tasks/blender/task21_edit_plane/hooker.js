// Blender搜索监控钩子脚本
// 用于监听Blender的搜索操作并检测特定查询
// 获取函数地址

(function() {
    const TARGET_ADD = "Plane";
    const TARGET_MODE = 1;
    const ORIG_VERTEX = [[1,1,0],[-1,-1,0]]
    const NEW_VERTEX = [[2,2,0],[-2,-2,0]]
    // 全局变量
    let searchFuncFound = false;
    let addElement = false;
    let changeMode = false;
    let preVertex = [];
    let preOrigVertex = [];
    let processVertex = [];
    let vertexCount = 0;
    
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
        // 查找 mode_set_ex 函数在模块中的位置
        let mode_set_ex = getFunctionAddress("_ZN7blender2ed6object11mode_set_exEP8bContext11eObjectModebP10ReportList");
        // 查找 apply_raw_diff_v3 函数在模块中的位置
        let apply_raw_diff_v3 = getFunctionAddress("_ZL17apply_raw_diff_v3PfiPKfS1_");


        // 如果没找到
        if (!BKE_mesh_add) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到增加元素函数"
            });
            return null;
        }

        if (!mode_set_ex) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到更改视图模式函数"
            });
            return null;
        }

        if (!apply_raw_diff_v3) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到点位置更改函数"
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
            address: mode_set_ex.toString(),
            message: "找到更改视图模式函数"
        });

        sendEvent("function_found", {
            address: apply_raw_diff_v3.toString(),
            message: "找到点位置更改函数"
        });

        
        return [BKE_mesh_add, mode_set_ex, apply_raw_diff_v3];
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

    function copyArray(arr1, arr2) {
        for (let i = 0; i < arr1.length; i++,arr1.pop()); 
        for(let i = 0; i < arr2.length; arr1.push(arr2[i]),i++);
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
            onEnter: function(args) {
                try {
                    if (addElement) {
                        var mode = args[1].toInt32()
                        
                        if (mode == TARGET_MODE) {
                            // 发送查询检测事件
                            sendEvent("change_mode_detected", {
                                object_mode: mode,
                                message: `检测更改视图模式: mode = ${mode}`
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
                    if (retval)
                        changeMode = true;                    
                    sendEvent("change_mode_finished", {
                        success: retval,
                        message: `检测到更改视图模式结束`
                    });
                } catch (error) {
                    sendEvent("error", {
                        error_type: "general_error",
                        message: `执行错误: ${error.message}`
                    });
                }
            }
        });

        Interceptor.attach(funcAddrs[2], {
            onEnter: function(args) {
                try {
                    if (changeMode) {
                        var origVertexPtr = args[0];
                        var newVertexptr = args[2];
                        var origVertex = [];
                        var newVertex = [];

                        for(var i = 0; i < 3; i++) {
                            origVertex.push(parseInt(origVertexPtr.add(i*4).readFloat(),10));
                            newVertex.push(parseInt(newVertexptr.add(i*4).readFloat(),10));
                        }
                                                
                        if(compareArrays(origVertex,preVertex)){
                            copyArray(processVertex,preOrigVertex);
                            vertexCount--;
                        }
                        
                        if((compareArrays(processVertex,ORIG_VERTEX[0]) && compareArrays(newVertex,NEW_VERTEX[0])) ||
                            (compareArrays(processVertex,ORIG_VERTEX[1]) && compareArrays(newVertex,NEW_VERTEX[1]))) {
                            vertexCount++;
                            copyArray(preVertex,newVertex);
                            copyArray(preOrigVertex,processVertex)
                            
                            // preVertex = newVertex;
                            // preOrigVertex = processVertex;
                            // processVertex = [];
                            // 发送查询检测事件
                            sendEvent("edit_vertex_detected", {
                                orig_vertex : processVertex,
                                new_vertex : newVertex,
                                message: `检测到点位置更改由 ${origVertex} 变为 ${newVertex}`
                            });
                            for(;processVertex.length;processVertex.pop());
                        }
                        if(processVertex.length == 0 && (compareArrays(origVertex,ORIG_VERTEX[0]) || compareArrays(origVertex,ORIG_VERTEX[1])))
                            copyArray(processVertex,origVertex); 
                            // processVertex = origVertex;
                    }
                } catch (error) {
                    sendEvent("error", {
                        error_type: "general_error",
                        message: `执行错误: ${error.message}`
                    });
                }
            },
            onLeave: function() {
                try {
                    if (vertexCount == 2){
                        sendEvent("edit_vertex_finished", {
                            success: true,
                            message: `检测到点位置更改结束`
                        });
                        vertexCount = 0;
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