// Blender搜索监控钩子脚本
// 用于监听Blender的搜索操作并检测特定查询
// 获取函数地址

(function() {
    const TARGET_FILE_PATH = "/home/agent/blender-git/meterial/文件收纳盒/文件收纳盒.blend";
    const TARGET_IMPORT_FILES = [
        "/home/agent/blender-git/meterial/文件收纳盒/文件收纳盒 (1).obj",
        "/home/agent/blender-git/meterial/文件收纳盒/文件收纳盒 (2).obj",
    ]
    // 全局变量
    let searchFuncFound = false;
    let openFile = false;
    let preImport = "";
    let importCount = 0;
    
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
        // 查找 blo_filedata_from_file 函数在模块中的位置
        let blo_filedata_from_file = getFunctionAddress("_Z22blo_filedata_from_filePKcP19BlendFileReadReport");
        let OBJ_import = getFunctionAddress("_Z10OBJ_importP8bContextPK15OBJImportParams");

        // 如果没找到
        if (!blo_filedata_from_file) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到打开文件函数"
            });
            return null;
        }
        if (!OBJ_import) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到导入OBJ文件函数"
            });
            return null;
        }
                
        // 报告找到函数
        searchFuncFound = true;
        sendEvent("function_found", {
            address: blo_filedata_from_file.toString(),
            message: "找到打开文件函数"
        });
        sendEvent("function_found", {
            address: OBJ_import.toString(),
            message: "找到导入OBJ文件函数"
        });
        
        return [blo_filedata_from_file, OBJ_import];
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
                    var filepath = Memory.readCString(args[0]); 

                    if (filepath == TARGET_FILE_PATH) {
                        // 发送事件
                        sendEvent("open_file_detected", {
                            file_path: filepath,
                            message: `检测到打开指定文件: ${filepath}`
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
                        openFile = true;
                        sendEvent("open_file_finished", {
                            retval: true,
                            message: `检测到打开文件完成`
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
                    if(openFile) {
                        var obj_import_params_ptr = args[1];
                        var filepath_ptr = ptr(obj_import_params_ptr).add(0);  // filepath 在结构体中的偏移量为 0
                        var filepath = Memory.readUtf8String(filepath_ptr);  

                        if (filepath != preImport && (filepath == TARGET_IMPORT_FILES[0] || filepath == TARGET_IMPORT_FILES[1])) {
                            preImport = filepath;
                            importCount++;
                            // 发送事件
                            sendEvent("import_file_detected", {
                                file_path: filepath,
                                message: `检测到导入文件: ${filepath}`
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
                    if(importCount == TARGET_IMPORT_FILES.length) {
                        sendEvent("import_file_finished", {
                            success: true,
                            message: `检测到导入文件完成`
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