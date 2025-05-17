(function() {
    // 脚本设置 - 目标函数
    const FUNCTION_NAME_sessionimpl = "_ZN10BitTorrent11SessionImpl15addTorrent_implERKNS_17TorrentDescriptorERKNS_16AddTorrentParamsE";
    const FUNCTION_NAME_initLoadTorrentParams = "_ZN10BitTorrent11SessionImpl21initLoadTorrentParamsERKNS_16AddTorrentParamsE";
    const FUNCTION_TorrentInfo_name = "_ZNK10BitTorrent11TorrentInfo4nameEv"
    const OFFSET_TO_LoadTorrentParams = 0x358;


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

    // 初始化监控钩子函数
    function initAddTorrentHook() {
        const funcAddr = getFunctionAddress(FUNCTION_NAME_sessionimpl);
        
        const initLoadTorrentParamsAddr= getFunctionAddress(FUNCTION_NAME_initLoadTorrentParams);
        const torrentInfoNameAddr= getFunctionAddress(FUNCTION_TorrentInfo_name);
        let isAddTorrentCalled = false;
        
        // 监控添加种子文件的函数
        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                this.source = args[0];
                isAddTorrentCalled = true;
                console.log("source:", this.source);
                sendEvent("add_torrent_called", {
                    message: "拦截到添加种子文件的函数调用"
                });
            },

            onLeave: function(retval) {
                console.log("source:", this.source);
                isAddTorrentCalled = false;
            }
        });

        // 监控种子加载参数的函数
        Interceptor.attach(initLoadTorrentParamsAddr, {
            onEnter: function(args) {
                if (isAddTorrentCalled) {
                    console.log("initLoadTorrentParams called from within addTorrent!");
                } 
            },
            onLeave: function(retval) {
                // 当种子加载参数函数完成时
                if (isAddTorrentCalled) {
                const torrentParamsName = retval.add(OFFSET_TO_LoadTorrentParams);
                const torrentName = readQString(torrentParamsName);
                   console.log("torrentName:", torrentName);
                   if(torrentName){
                    sendEvent("add_torrent_result", {
                        message: "添加种子到会话函数正确返回",
                        torrent_data: torrentName 
                    });
                   }
                }
                
                
            }
        });
        Interceptor.attach(torrentInfoNameAddr, {
            onEnter: function(args) {
                if (isAddTorrentCalled) {
                    console.log("TorrentInfo name() called from within addTorrent!");
                } 
            },
            onLeave: function(retval) {
                // 当获取种子名称函数完成时
                if (isAddTorrentCalled) {
                const torrentParamsName = retval;
                const torrentName = readQString(torrentParamsName);
                   console.log("torrentName:", torrentName);
                   if(torrentName){
                    sendEvent("add_torrent_result", {
                        message: "添加种子到会话函数正确返回",
                        torrent_data: torrentName 
                    });
                   }
                }
                
            }
        });
    }
    
    // 启动脚本
    function initHook() {
        sendEvent("script_initialized", {
            message: "qBittorrent 添加种子文件监控脚本已启动"
        });
        
        // 初始化钩子
        initAddTorrentHook();
        
        sendEvent("all_hooks_installed", {
            message: "所有监控钩子安装完成，等待添加种子文件操作..."
        });
    }

    initHook();
})();