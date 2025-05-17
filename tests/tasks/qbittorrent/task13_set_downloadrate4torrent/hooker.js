(function() {
    // 脚本设置 - 目标函数
    const FUNCTION_NAME_SET_RATE4TORRENT = "_ZN10BitTorrent11TorrentImpl16setDownloadLimitEi";
    const OFFSET_TO_TORRENT_NAME  = 0xa8
    const OFFSET_TO_DOWNLOAD_LIMIT = 0x8c0

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
    
    function readStdString(stringPtr) {
        try {
            // 对于大多数std::string实现，内存布局如下：
            // - 短字符串可能直接存储在对象内部
            // - 长字符串会有一个指向堆内存的指针
            
            // 首先检查是否为小字符串优化(SSO)
            const capacity = stringPtr.add(16).readU64(); // 通常在此偏移位置保存容量
            const isSmallString = capacity > 22; // 根据具体实现可能需要调整此值
            
            let dataPtr;
            if (isSmallString) {
                // 长字符串，从第一个8字节读取指针
                dataPtr = stringPtr.readPointer();
            } else {
                // 短字符串，数据直接存储在对象内
                dataPtr = stringPtr;
            }
            
            // 读取字符串内容
            return dataPtr.readCString();
        } catch (e) {
            sendEvent("error", {
                error_type: "std_string_read_error",
                message: `读取std::string错误: ${e.message}`
            });
            return null;
        }
    }
  
    

    // 初始化下载速率设置监控钩子
    function initSetDownloadRateHook() {
        const funcAddr = getFunctionAddress(FUNCTION_NAME_SET_RATE4TORRENT);

        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                this.source = args[0];
                this.name = this.source.add(OFFSET_TO_TORRENT_NAME)
                const torrent_name = readStdString(this.name)
                console.log("torrent_name:", torrent_name);
                this.download_limit = this.source.add(OFFSET_TO_DOWNLOAD_LIMIT)
                const download_limit = Memory.readInt(this.download_limit)/1024
                console.log("download_limit_before:", download_limit);
                this.new_limit = args[1].toInt32()/1024;
                console.log("new_download_limit:", this.new_limit);
               
                sendEvent("set_downloadrate_called", {
                    message: "拦截到设置种子下载速率函数调用",
                    name: torrent_name,
                    download_limit_before: download_limit,
                    new_download_limit: this.new_limit
                });
            },

            onLeave: function(retval) {
                const torrent_name = readStdString(this.name)
                console.log("torrent_name:", torrent_name);
                const download_limit = Memory.readInt(this.download_limit)/1024
                console.log("download_limit_after:", download_limit);
                sendEvent("set_downloadrate_success", {
                    message: "设置种子下载速率函数正确返回",
                    download_limit_after: download_limit,
                    name: torrent_name,
                    new_limit_applied: this.new_limit === download_limit
                });
            }
        });
    }
    
    // 启动脚本
    function initHook() {
        sendEvent("script_initialized", {
            message: "qBittorrent 种子下载速率设置监控脚本已启动"
        });
        
        // 初始化钩子
        initSetDownloadRateHook();
        
        sendEvent("all_hooks_installed", {
            message: "所有监控钩子安装完成，等待设置下载速率操作..."
        });
    }

    initHook();
})();