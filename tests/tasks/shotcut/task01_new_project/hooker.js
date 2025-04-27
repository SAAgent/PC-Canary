// shotcut创建新项目监控钩子脚本
// 用于监听shotcut的创建新项目操作并检测任何查询

(function() {
    // 脚本常量设置
    const MAX_CHARS = 50;         // 最大读取字符数
    const FUNTION_NAME = "_ZN10MainWindow10newProjectERK7QStringb"
    
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
                message: "无法找到MainWindow::newProject函数"
            });
            return null;
        }
        
        // 报告找到函数
        funcFound = true;
        sendEvent("function_found", {
            address: FuncAddr.toString(),
            message: "找到MainWindow::newProject函数"
        });
        
        return FuncAddr;
    }
    
    // 读取QString字符串内容
    function readQString(Ptr, offset = 8) {
        const q_str_ptr = Ptr.add(offset);
        const q_str = q_str_ptr.readPointer().readUtf16String(-1);
        return q_str;
    }
    
    // 初始化钩子并立即执行
    function initHook() {
        sendEvent("script_initialized", {
            message: "shotcut创建新项目监控脚本已启动"
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
                        message: "拦截到创建项目函数调用"
                    });
                    
                    // 获取文件名称
                    const filename = args[1];
                    
                    let qstring_name = readQString(filename, 8);
                    
                    if (qstring_name != null) {
                        // 直接发送查询检测事件，不做任何判断
                        sendEvent("funtion_key_word_detected", {
                            message: `检测到创建新项目`,
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