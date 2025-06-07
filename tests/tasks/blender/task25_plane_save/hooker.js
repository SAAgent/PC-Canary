// Blender搜索监控钩子脚本
// 用于监听Blender的搜索操作并检测特定查询
// 获取函数地址

(function() {
    const TARGET_ADD = "Plane";
    const TARGET_TYPE = 24;
    const TARGET_LOCATION = [0,0,-2];
    const TARGET_FILE_PATH = "/home/agent/blender-git/Plane.blend";

    // 全局变量
    let searchFuncFound = false;
    let addElement = false;
    let locationSet = false;
    let modifierAdd = false;
    
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
        // 查找 modifier_add 函数在模块中的位置
        let modifier_add = getFunctionAddress("_ZN7blender2ed6object12modifier_addEP10ReportListP4MainP5SceneP6ObjectPKci");
        // 查找 BLO_write_file 函数在模块中的位置
        let BLO_write_file = getFunctionAddress("_Z14BLO_write_fileP4MainPKciPK20BlendFileWriteParamsP10ReportList");


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

        if (!modifier_add) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到增加Modifier函数"
            });
            return null;
        }
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
            address: BKE_mesh_add.toString(),
            message: "找到增加元素函数"
        });
        sendEvent("function_found", {
            address: BKE_object_to_mat4.toString(),
            message: "找到物体位置更改函数"
        });

        sendEvent("function_found", {
            address: modifier_add.toString(),
            message: "找到增加Modifier函数"
        });
        sendEvent("function_found", {
            address: BLO_write_file.toString(),
            message: "找到另存文件函数"
        });
        
        
        return [BKE_mesh_add,BKE_object_to_mat4, modifier_add,BLO_write_file];
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
                    if(addElement) {
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

                        if (name.toLowerCase() == TARGET_ADD.toLowerCase() && compareArrays(location,TARGET_LOCATION)) {
                            locationSet = true;
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
            onEnter: function(args) {
                try {
                    if (locationSet) {
                        var modifier_type = args[5].toInt32();
                        sendEvent("add_modifier_detected", {
                            type: modifier_type == TARGET_TYPE,
                            message: `增加Modifier，其type为: ${modifier_type}`
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
                    if (locationSet) {
                        if(!retval.isNull())
                            modifierAdd = true;
                        // 发送查询检测事件
                        sendEvent("add_modifier_finished", {
                            success: !retval.isNull(),
                            message: `增加Modifier结束`
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
            onEnter: function(args) {
                try {
                    if(modifierAdd){
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
                    if(modifierAdd){
                        // 获取函数的返回值（假设返回值是一个 32 位整数）
                        var returnValue = retval.toInt32();

                        if (returnValue != 0) {
                            sendEvent("saveas_file_finished", {
                                retval: true,
                                message: `检测到另存文件结束`
                            });
                        } 
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