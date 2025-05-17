(function() {
    // 脚本设置 - 目标函数
    const FUNCTION_NAME_SET_UPLOAD_RATES = "_ZN10BitTorrent11SessionImpl25setGlobalUploadSpeedLimitEi";
    const FUNCTION_NAME_GLOBAL_UPLOAD_SPEED_LIMIT = "_ZNK10BitTorrent11SessionImpl22globalUploadSpeedLimitEv";
    const OFFSET_TO_GLOBAL_UPLOAD_SPEED_LIMIT = 0xa98;

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
    
    // 初始化设置上传速率监控钩子
    function initSetUploadRatesHook() {
        const setRatesAddr = getFunctionAddress(FUNCTION_NAME_SET_UPLOAD_RATES);
        const getUploadLimitAddr = getFunctionAddress(FUNCTION_NAME_GLOBAL_UPLOAD_SPEED_LIMIT);

        let isSetUploadRatesCalled = false;
        
        // 监控设置上传速率的函数
        Interceptor.attach(setRatesAddr, {
            onEnter: function(args) {
                this.source = args[0];
                this.requestedLimit = args[1].toInt32();
                isSetUploadRatesCalled = true;
                
                sendEvent("set_upload_rates_called", {
                    message: "拦截到设置上传速率的函数调用",
                    requested_limit: this.requestedLimit
                });
            },

            onLeave: function(retval) {
                console.log("源对象:", this.source);
                
                // 读取设置后的上传速率
                const uploadRatesAddr = this.source.add(OFFSET_TO_GLOBAL_UPLOAD_SPEED_LIMIT);
                const uploadRatesValue = Memory.readInt(uploadRatesAddr);
                console.log("上传速率值:", uploadRatesValue);
                
                sendEvent("set_upload_rates_result", {
                    message: "成功设置上传速率",
                    upload_rates_value: uploadRatesValue
                });
                isSetUploadRatesCalled = false;
            }
        });
    }
    
    // 启动脚本
    function initHook() {
        sendEvent("script_initialized", {
            message: "qBittorrent 设置上传速率监控脚本已启动"
        });
        
        // 初始化钩子
        initSetUploadRatesHook();
        
        sendEvent("all_hooks_installed", {
            message: "所有监控钩子安装完成，等待设置上传速率操作..."
        });
    }

    initHook();
})();