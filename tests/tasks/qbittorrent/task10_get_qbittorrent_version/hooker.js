(function() {
    // 脚本设置 - 目标函数
    const FUNCTION_NAME_GET_VERSION = "_ZNK11AboutDialog23copyVersionsToClipboardEv"; // 获取版本信息的函数
    const FUNCTION_NAME_SET_CLIPBOARD_TEXT = "_ZN10QClipboard7setTextERK7QStringNS_4ModeE"; // 设置剪贴板文本的函数
    
    // 向评估系统发送事件
    function sendEvent(eventType, data = {}) {
        const payload = {
            event: eventType,
            ...data,
            timestamp: new Date().getTime()
        };
        send(payload);
    }
    
    // 查找函数地址
    function getFunctionAddress(functionName) {
        let funcAddr = Module.findExportByName(null, functionName);
        if (funcAddr) {
            sendEvent("function_found", {
                function_name: functionName,
                address: funcAddr.toString(),
                message: `找到函数 ${functionName} 的实际地址`
            });
        } else {
            sendEvent("error", {
                error_type: "function_not_found",
                message: `无法找到函数 ${functionName}`
            });
        }
        return funcAddr;
    }

    // 读取QString字符串内容
    function readQString(queryPtr, offset = 8) {
        const MAX_CHARS = 1000; // 最大读取字符数
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
                    // 包含常见空白字符：空格(32+)、换行(10)、回车(13)、制表符(9)
                    if ((c >= 32 && c < 0xFFFF) || c === 10 || c === 13 || c === 9) {
                        str += String.fromCharCode(c);
                    } else if (c === 0) { // 字符串结束
                        break;
                    } else {
                        valid = false; // 遇到未预期的控制字符
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

    // 初始化获取qBittorrent版本的监控钩子
    function initGetVersionHook() {
        // 获取目标函数地址
        const getVersionAddr = getFunctionAddress(FUNCTION_NAME_GET_VERSION);
        const setClipboardTextAddr = getFunctionAddress(FUNCTION_NAME_SET_CLIPBOARD_TEXT);

        // 标记是否已调用获取版本信息的函数
        let isGetVersionCalled = false;
        
        // 监控版本信息复制到剪贴板的函数
        Interceptor.attach(getVersionAddr, {
            onEnter: function(args) {
                this.source = args[0]; // AboutDialog对象
                isGetVersionCalled = true;
                console.log("拦截到获取版本信息的函数调用");
                
                sendEvent("get_qbittorrent_version", {
                    message: "拦截到获取版本信息的函数调用"
                });
            },

            onLeave: function(retval) {
                console.log("AboutDialog对象:", this.source);
                isGetVersionCalled = false;
            }
        });

        // 监控设置剪贴板文本的函数以获取版本信息
        Interceptor.attach(setClipboardTextAddr, {
            onEnter: function(args) {
                // 检查是否在获取版本信息的上下文中
                if (isGetVersionCalled) {
                    this.textPtr = args[1]; // 指向版本信息文本的指针
                    const versionText = readQString(this.textPtr);
                    console.log("qBittorrent版本信息:", versionText);
                    
                    // 发送获取到的版本信息
                    sendEvent("get_qbittorrent_version_result", {
                        message: "成功获取qBittorrent版本信息",
                        qbittorrent_version: versionText
                    });
                }
            }
        });
    }
    
    // 启动脚本
    function initHook() {
        sendEvent("script_initialized", {
            message: "qBittorrent 版本获取监控脚本已启动"
        });
        
        // 初始化钩子
        initGetVersionHook();
        
        sendEvent("all_hooks_installed", {
            message: "所有监控钩子安装完成，等待获取版本操作..."
        });
    }

    initHook();
})();