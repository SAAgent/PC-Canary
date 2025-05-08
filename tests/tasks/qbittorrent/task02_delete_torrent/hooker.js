(function() {
    // 脚本设置 - 目标函数
    const FUNCTION_NAME_REMOVE_TORRENT = "_ZN10BitTorrent11SessionImpl13removeTorrentERKNS_9TorrentIDENS_19TorrentRemoveOptionE";

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
    function initRemoveTorrentHook() {
        // 获取函数地址
        const removeTorrentAddr = getFunctionAddress(FUNCTION_NAME_REMOVE_TORRENT);
        
        Interceptor.attach(removeTorrentAddr, {
            onEnter: function(args) {
                // 保存 this 指针供 onLeave 使用
                this.sessionImpl = args[0];
                
                console.log("source:", this.source);
                
            
                sendEvent("add_torrent_called", {
                    message: "拦截到删除会话框种子函数调用",
                    torrent_data: this.sessionImpl
                });
            },
    
            onLeave: function(retval) {
                // 检查返回值 (bool)
                const success = retval.toInt32() !== 0;

                if(success){
                // 发送事件通知
                sendEvent("remove_torrent_result", {
                    message: "删除种子成功",
                    result: success
                });
            }
                else{
                    sendEvent("remove_torrent_failed", {
                        error_type: "remove_torrent_failed",
                        message: "删除种子失败"
                    });
            }
        }
        });
    }
    


    // 启动脚本
    function initHook() {
        sendEvent("script_initialized", {
            message: "qBittorrent 种子添加监控脚本已启动"
        });
        

        // 初始化钩子
        initRemoveTorrentHook();
        
    
    }

    initHook();
})();