(function() {
    // 脚本设置 - 目标函数
    const FUNCTION_NAME_STOP_ALL_TORRENTS = "_ZN18TransferListWidget19stopVisibleTorrentsEv";
    const FUNCTION_NAME_STOP_TORRENT = "_ZN10BitTorrent11TorrentImpl4stopEv";
    const OFFSET_TO_TORRENT_INFO_NAME = 0xa8;
    const OFFSET_TO_TORRENT_STOP = 0x530;
    let statusArray = [];

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
    
    // 检查所有种子是否成功停止
    function checkAllSuccess() {
        return statusArray.every(status => status === 1);
    }
    
    // 初始化监控钩子函数
    function initStopAllTorrentHook() {
        const funcAddr = getFunctionAddress(FUNCTION_NAME_STOP_ALL_TORRENTS);
        const stopTorrentAddr = getFunctionAddress(FUNCTION_NAME_STOP_TORRENT);

        let isStopVisibleTorrentsCalled = false;
        
        // 监控停止所有种子的函数
        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                this.source = args[0];
                isStopVisibleTorrentsCalled = true;
                
                sendEvent("stop_all_torrents_called", {
                    message: "拦截到暂停所有种子的函数调用"
                });
            },

            onLeave: function(retval) {
                console.log("source:", this.source);
                
                sendEvent("stop_all_torrents", {
                    message: "成功暂停所有种子文件"
                });
                isStopVisibleTorrentsCalled = false;
            }
        });

        // 监控单个种子的停止函数
        Interceptor.attach(stopTorrentAddr, {
            onEnter: function(args) {
                // 检查是否是从stopVisibleTorrents调用的
                if (isStopVisibleTorrentsCalled) {
                    this.torent = args[0];
                    console.log("[+] torrent->stop() called from within stopVisibleTorrents!");
                    console.log("  Torrent Object:", this);
                } 
            },
            onLeave: function(retval) {
                // 当单个种子停止函数完成时
                if (isStopVisibleTorrentsCalled) {
                    console.log("[+] torrent->stop() finished.");
                    const torrent_stop_status = this.torent.add(OFFSET_TO_TORRENT_STOP);
                    let stop_status = Memory.readU8(torrent_stop_status);
                    console.log("stop status: ", stop_status);
                    statusArray.push(stop_status);
                }
                
                // 检查是否所有种子都已成功停止
                if (checkAllSuccess()) {
                    sendEvent("stop_all_torrents_result", {
                        message: "已成功暂停所有种子下载",
                        success: 1
                    });
                }
            }
        });
    }
    
    // 启动脚本
    function initHook() {
        sendEvent("script_initialized", {
            message: "qBittorrent 暂停所有种子文件监控脚本已启动"
        });
        
        // 初始化钩子
        initStopAllTorrentHook();
        
        sendEvent("all_hooks_installed", {
            message: "所有监控钩子安装完成，等待暂停所有种子操作..."
        });
    }

    initHook();
})();