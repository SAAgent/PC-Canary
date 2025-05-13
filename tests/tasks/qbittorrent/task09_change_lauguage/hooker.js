(function() {
    // 脚本设置 - 目标函数
    const FUNCTION_NAME_SET_LANGUAGE = "_ZN11Preferences9setLocaleERK7QString";
    const FUNCTION_NAME_GET_LOCALE = "_ZNK11Preferences9getLocaleEv";

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
    
    // 初始化设置语言监控钩子
    function initSetLanguageHook() {
        const setLocaleAddr = getFunctionAddress(FUNCTION_NAME_SET_LANGUAGE);
        const getLocaleAddr = getFunctionAddress(FUNCTION_NAME_GET_LOCALE);

        // 监控设置语言的函数
        Interceptor.attach(setLocaleAddr, {
            onEnter: function(args) {
                this.source = args[0]; // Preferences对象
                this.localeArg = args[1]; // 语言参数
                
                // 获取请求设置的语言
                const requestedLocale = readQString(this.localeArg);
                console.log("请求设置语言为:", requestedLocale);
                
                sendEvent("change_language_called", {
                    message: "拦截到设置语言的函数调用",
                    requested_locale: requestedLocale
                });
            },

            onLeave: function(retval) {
                console.log("源对象:", this.source);
                
                // 获取设置后的语言
                if (getLocaleAddr) {
                    const getLocaleNative = new NativeFunction(getLocaleAddr, 'void', ["pointer", "pointer"]);
                    const qStringReturnValuePtr = Memory.alloc(Process.pointerSize);
                    getLocaleNative(qStringReturnValuePtr, this.source);
                    const localeStr = readQString(qStringReturnValuePtr);
                    console.log("设置后的语言:", localeStr);
                    
                    sendEvent("change_language_result", {
                        message: "成功设置语言",
                        locale: localeStr
                    });
                }
            }
        });
    }
    
    // 启动脚本
    function initHook() {
        sendEvent("script_initialized", {
            message: "qBittorrent 语言设置监控脚本已启动"
        });
        
        // 初始化钩子
        initSetLanguageHook();
        
        sendEvent("all_hooks_installed", {
            message: "所有监控钩子安装完成，等待设置语言操作..."
        });
    }

    initHook();
})();