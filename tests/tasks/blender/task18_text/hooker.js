// Blender搜索监控钩子脚本
// 用于监听Blender的搜索操作并检测特定查询
// 获取函数地址

(function() {
    const TARGET_MODE = 1;
    const TARGET_TYPE = 5;
    // 全局变量
    let searchFuncFound = false;
    let viewType = false;
    let changeView = false;
    let addElement = false;
    let changeMode = false;
    
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
        // 查找 axis_set_view 函数在模块中的位置
        let axis_set_view = getFunctionAddress("_Z13axis_set_viewP8bContextP6View3DP7ARegionPKfcciS6_i");
        // 查找 object_add_text_exec 函数在模块中的位置
        let object_add_text_exec = getFunctionAddress("_ZN7blender2ed6objectL20object_add_text_execEP8bContextP10wmOperator");
        // 查找 mode_set_ex 函数在模块中的位置
        let mode_set_ex = getFunctionAddress("_ZN7blender2ed6object11mode_set_exEP8bContext11eObjectModebP10ReportList");
        // 查找 text_update_edited 函数在模块中的位置
        let text_update_edited = getFunctionAddress("_ZL18text_update_editedP8bContextP6Object13eEditFontMode");


        // 如果没找到
        if (!axis_set_view) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到更新viewpoint函数"
            });
            return null;
        }

        if (!object_add_text_exec) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到增加text物体函数"
            });
            return null;
        }

        if (!mode_set_ex) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到更新视图函数"
            });
            return null;
        }

        if (!text_update_edited) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到更新文本函数"
            });
            return null;
        }
        
        // 报告找到函数
        searchFuncFound = true;
        sendEvent("function_found", {
            address: axis_set_view.toString(),
            message: "找到切换viewpoint函数"
        });

        sendEvent("function_found", {
            address: object_add_text_exec.toString(),
            message: "找到增加Text元素函数"
        });

        sendEvent("function_found", {
            address: mode_set_ex.toString(),
            message: "找到切换编辑视图函数"
        });
        
        sendEvent("function_found", {
            address: text_update_edited.toString(),
            message: "找到更新文本函数"
        });
        
        return [axis_set_view, object_add_text_exec, mode_set_ex, text_update_edited];
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
                    var type = args[4].toInt32();
                    
                    if (type == TARGET_TYPE) {
                        viewType = true;
                        // 发送查询检测事件
                        sendEvent("view_change_detected", {
                            type: type,
                            message: `检测到切换viewpoint`
                        });
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
                    if (viewType) {
                        changeView = true;
                        // 发送查询检测事件
                        sendEvent("view_change_finished", {
                            success: viewType,
                            message: `检测到切换viewpoint结束`
                        });
                    }
                    viewType = false;                    
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
                    if(changeView) {
                        if (!retval.isNull()) 
                            addElement = true;
    
                        sendEvent("add_element_detected", {
                            success: !retval.isNull(),
                            message: `检测到新增元素结束`
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
            onEnter: function(args) {
                try {
                    if (addElement) {
                        var mode = args[1].toInt32()
                        
                        if (mode == TARGET_MODE) {
                            // 发送查询检测事件
                            changeMode = true;
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

        Interceptor.attach(funcAddrs[3], {
            onEnter: function(args) {
                try {
                    if (changeMode) {
                        // 获取 obedit 的地址（假设是第一个参数）
                        var obedit = args[1];

                        // 计算 cu 的地址
                        var cu = obedit.add(0x178).readPointer(); // 替换为 cu 在 obedit 中的实际偏移量

                        // 获取 ef 的地址
                        var ef = cu.add(0x1C8).readPointer(); // 替换为 editfont 在 Curve 中的实际偏移量

                        // 读取 ef->textbuf 的值
                        var textbuf = ef.readPointer(); // 读取第一个字段的指针值

                        // 读取 ef->textbuf 的内容
                        var textLength = ef.add(0x3C).readInt(); // 假设 textbuf 的长度存储在偏移量 0x8 处
                        // 读取 textbuf 的内容
                        var text = "";
                        for (var i = 0; i < textLength; i++) {
                            var charCode = textbuf.add(i*4).readU8(); // 每个 UTF-32 字符占 4 字节
                            text += String.fromCodePoint(charCode); // 将 UTF-32 转换为字符串
                        }

                        sendEvent("change_text_detected", {
                            text: text,
                            message: `检测到编辑文本内容为: ${text}`
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