(function() {
    // 脚本设置 - 目标函数
    const FUNCTION_NAME_START_ALL_TORRENTS = "_ZN18TransferListWidget20startVisibleTorrentsEv";

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
    
  
    

    // 初始化AddTorrentManager::addTorrentToSession监控钩子
    function initStartAllTorrentHook() {
        const funcAddr = getFunctionAddress(FUNCTION_NAME_START_ALL_TORRENTS);
     

        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                this.source = args[0];
                
            },

            onLeave: function(retval) {
                console.log("source:", this.source);
                
            
                sendEvent("start_all_torrents", {
                    message: "成功启动所有种子文件下载",
                   
                });
            }
        });

    
    }
    


    // 启动脚本
    function initHook() {
        sendEvent("script_initialized", {
            message: "qBittorrent 种子添加监控脚本已启动"
        });
        

        // 初始化钩子
        initStartAllTorrentHook();
        
        sendEvent("all_hooks_installed", {
            message: "所有监控钩子安装完成，等待启动种子操作..."
        });
    }

    initHook();
})();