// Blender搜索监控钩子脚本
// 用于监听Blender的搜索操作并检测特定查询
// 获取函数地址

(function() {
    const TARGET_ADD = "Cylinder";
    const TARGET_TYPE = 4;
    // 全局变量
    let searchFuncFound = false;
    let addElement = false;
    let localView = false;
    let addMaterial = false;
    
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
        // 查找 view3d_localview_init 函数在模块中的位置
        let view3d_localview_init = getFunctionAddress("_ZL21view3d_localview_initPK9DepsgraphP15wmWindowManagerP8wmWindowP4MainPK5SceneP9ViewLayerP7ScrAreabiP10ReportList");
        // 查找 BKE_material_add 函数在模块中的位置
        let BKE_material_add = getFunctionAddress("_Z16BKE_material_addP4MainPKc");
        // 查找 ED_view3d_shade_update 函数在模块中的位置
        let ED_view3d_shade_update = getFunctionAddress("_Z22ED_view3d_shade_updateP4MainP6View3DP7ScrArea");


        // 如果没找到
        if (!BKE_mesh_add) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到增加元素函数"
            });
            return null;
        }

        if (!view3d_localview_init) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到切换局部视图函数"
            });
            return null;
        }

        if (!BKE_material_add) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到增加Material函数"
            });
            return null;
        }

        if (!ED_view3d_shade_update) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到更新视图函数"
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
            address: view3d_localview_init.toString(),
            message: "找到切换局部视图函数"
        });

        sendEvent("function_found", {
            address: BKE_material_add.toString(),
            message: "找到增加Material函数"
        });

        sendEvent("function_found", {
            address: ED_view3d_shade_update.toString(),
            message: "找到更新视图函数"
        });
        
        return [BKE_mesh_add,view3d_localview_init , BKE_material_add, ED_view3d_shade_update];
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
                        if (retval.toInt32() == 1) 
                            localView = true;
                        sendEvent("local_view_detected", {
                            success: retval.toInt32() == 1,
                            message: `检测到切换局部视图结束`
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

        Interceptor.attach(funcAddrs[2], {
            onLeave: function(retval) {
                try {
                    if (localView) {
                        // 发送查询检测事件
                        sendEvent("add_material_detected", {
                            success: !retval.isNull(),
                            message: `增加Material结束`
                        });
                        if(!retval.isNull()) {
                            addMaterial = true;
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

        Interceptor.attach(funcAddrs[3], {
            onEnter: function(args) {
                try {
                    if (addMaterial) {
                        var v3d = args[1]; // View3D* 是第二个参数
                        var shading = v3d.add(0x118); // 获取 v3d->shading 的地址
                        var typeValue = shading.readU8(); // 读取 shading.type

                        sendEvent("change_view_detected", {
                            success: typeValue == TARGET_TYPE,
                            message: `检测到修改View视图`
                        });
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