// Telegram搜索监控钩子脚本
// 用于监听Telegram的搜索操作并检测任何查询

(function() {
    // 脚本常量设置
    const MAX_CHARS = 50;         // 最大读取字符数
    
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
        // 尝试直接通过导出符号查找
        let searchFuncAddr = Module.findExportByName(null, "_ZN7Dialogs6Widget6searchEbNS_18SearchRequestDelayE");
        
        // 如果没找到，尝试扫描模块
        if (!searchFuncAddr) {
            sendEvent("function_search_start", {
                message: "正在查找Widget::search函数..."
            });
            
            // 遍历模块
            Process.enumerateModules({
                onMatch: function(module) {
                    if (module.name.includes("Telegram")) {
                        sendEvent("module_found", {
                            module_name: module.name,
                            base_address: module.base.toString()
                        });
                        
                        // 这里可以添加特征码搜索
                        // 简化起见，省略实现
                    }
                },
                onComplete: function() {}
            });
            
            // 如果仍未找到，报告错误
            if (!searchFuncAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "无法找到Widget::search函数"
                });
                return null;
            }
        }
        
        // 报告找到函数
        searchFuncFound = true;
        sendEvent("search_function_found", {
            address: searchFuncAddr.toString(),
            message: "找到Widget::search函数"
        });
        
        return searchFuncAddr;
    }
    
    // 读取QString字符串内容
    function readQString(queryPtr, offset = 8) {
        try {
            const addr = queryPtr.add(offset);
            const possiblePtr = addr.readPointer();
            
            if (possiblePtr.isNull()) {
                return null;
            }
            
            // 尝试读取UTF-16字符串
            let str = "";
            let valid = true;
            
            for (let i = 0; i < MAX_CHARS; i++) {
                try {
                    const c = possiblePtr.add(i * 2).readU16();
                    if (c >= 32 && c < 0xFFFF) { // 可打印字符
                        str += String.fromCharCode(c);
                    } else if (c === 0) { // 字符串结束
                        break;
                    } else {
                        valid = false;
                        break;
                    }
                } catch (e) {
                    valid = false;
                    break;
                }
            }
            
            return valid && str.length > 0 ? str : null;
        } catch (e) {
            sendEvent("error", {
                error_type: "memory_read_error",
                message: `读取内存错误: ${e.message}`
            });
            return null;
        }
    }
    
    // 初始化钩子并立即执行
    function initHook() {
        sendEvent("script_initialized", {
            message: "Telegram搜索监控脚本已启动"
        });
        
        // 查找搜索函数
        const searchFuncAddr = findSearchFunction();
        if (!searchFuncAddr) {
            return;
        }
        
        // 偏移量设置 - 基于分析结果
        const SEARCH_STATE_OFFSET = 672;  // _searchState相对于Widget的偏移量
        const QUERY_OFFSET = 48;          // query相对于_searchState的偏移量
        const TOTAL_QUERY_OFFSET = 720;   // query相对于Widget的总偏移量
        
        // 安装搜索函数钩子
        Interceptor.attach(searchFuncAddr, {
            onEnter: function(args) {
                try {
                    sendEvent("search_function_called", {
                        message: "拦截到搜索函数调用"
                    });
                    
                    // 获取this指针
                    const widgetPtr = args[0];
                    
                    // 计算query地址
                    const queryPtr = widgetPtr.add(TOTAL_QUERY_OFFSET);
                    
                    // 读取查询字符串
                    const query = readQString(queryPtr);
                    
                    if (query) {
                        // 直接发送查询检测事件，不做任何判断
                        sendEvent("search_query_detected", {
                            query: query,
                            message: `检测到搜索查询: ${query}`
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
            message: "钩子安装完成，等待搜索操作..."
        });
    }
    
    // 立即执行钩子初始化
    initHook();
})();