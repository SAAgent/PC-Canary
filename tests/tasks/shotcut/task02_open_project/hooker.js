// shotcut创建新项目监控钩子脚本
// 用于监听shotcut的创建新项目操作并检测任何查询

(function() {
    // 脚本常量设置
    const MAX_CHARS = 50;         // 最大读取字符数
    const FUNTION_NAME = "_ZN10MainWindow4openE7QStringPKN3Mlt10PropertiesEbb"
    
    // 全局变量
    let funcFound = false;
    
    // 向评估系统发送事件
    function sendEvent(eventType, data = {}) {
        const payload = {
            event: eventType,
            ...data,
            timestamp: new Date().getTime()
        };
        send(payload);
    }
    
    // 查找MainWindow::newProject函数
    function getFunction() {
        // 尝试直接通过导出符号查找
        let FuncAddr = DebugSymbol.getFunctionByName(FUNTION_NAME);
        
        // 如果没找到，报错
        if (!FuncAddr) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到MainWindow::open函数"
            });
            return null;
        }
        
        // 报告找到函数
        funcFound = true;
        sendEvent("function_found", {
            address: FuncAddr.toString(),
            message: "找到MainWindow::open函数"
        });
        
        return FuncAddr;
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
            message: "shotcut打开项目监控脚本已启动"
        });
        
        // 查找搜索函数
        const funcAddr = getFunction();
        if (!funcAddr) {
            return;
        }
        
        // 安装搜索函数钩子
        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                try {
                    sendEvent("function_called", {
                        message: "拦截到打开项目函数调用"
                    });
                    
                    // 获取this指针
                    const filename = args[1];
                    
                    let qstring_name = readQString(filename, 8);
                    
                    if (qstring_name != null) {
                        // 直接发送查询检测事件，不做任何判断
                        sendEvent("funtion_key_word_detected", {
                            message: `检测到打开项目`,
                            filename: qstring_name
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