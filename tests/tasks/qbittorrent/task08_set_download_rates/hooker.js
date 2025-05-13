(function() {
    // 脚本设置 - 目标函数
    const FUNCTION_NAME_SET_DOWNLOAD_RATES = "_ZN10BitTorrent11SessionImpl27setGlobalDownloadSpeedLimitEi";
    const OFFSET_TO_GLOBAL_DOWNLOAD_SPEED_LIMIT = 0xa78;

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

    // 初始化设置下载速率监控钩子
    function initSetDownloadRatesHook() {
        const funcAddr = getFunctionAddress(FUNCTION_NAME_SET_DOWNLOAD_RATES);

        // 监控设置下载速率的函数
        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                this.source = args[0];
                this.requestedLimit = args[1].toInt32();
                
                sendEvent("set_download_rates_called", {
                    message: "拦截到设置下载速率的函数调用",
                    requested_limit: this.requestedLimit
                });
            },

            onLeave: function(retval) {
                console.log("源对象:", this.source);
                
                // 读取设置后的下载速率
                const downloadRatesAddr = this.source.add(OFFSET_TO_GLOBAL_DOWNLOAD_SPEED_LIMIT);
                const downloadRatesValue = Memory.readInt(downloadRatesAddr);
                console.log("下载速率值:", downloadRatesValue);
                
                sendEvent("set_download_rates_result", {
                    message: "成功设置下载速率",
                    download_rates_value: downloadRatesValue
                });
            }
        });
    }
    
    // 启动脚本
    function initHook() {
        sendEvent("script_initialized", {
            message: "qBittorrent 设置下载速率监控脚本已启动"
        });
        
        // 初始化钩子
        initSetDownloadRatesHook();
        
        sendEvent("all_hooks_installed", {
            message: "所有监控钩子安装完成，等待设置下载速率操作..."
        });
    }

    initHook();
})();