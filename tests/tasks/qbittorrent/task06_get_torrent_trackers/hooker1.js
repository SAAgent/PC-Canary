(function() {
    // 脚本设置 - 目标函数
    const FUNCTION_NAME_GET_TRACKERS = "_ZN17TrackerListWidget14copyTrackerUrlEv";
    const FUNCTION_NAME_SET_CLIPBOARD_TEXT = "_ZN10QClipboard7setTextERK7QStringNS_4ModeE";
    const OFFSET_TO_TORRENT_INFO_NAME = 0xa8;
    const OFFSET_TO_TORRENT_STATUS = 0x530;

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
    
    // 初始化获取种子Trackers钩子函数
    function initGetTrackerHook() {
        const trackerFuncAddr = getFunctionAddress(FUNCTION_NAME_GET_TRACKERS);
        const clipboardFuncAddr = getFunctionAddress(FUNCTION_NAME_SET_CLIPBOARD_TEXT);

        let isGetTrackersCalled = false;
        
        // 监控获取Tracker的函数
        Interceptor.attach(trackerFuncAddr, {
            onEnter: function(args) {
                this.source = args[0];
                isGetTrackersCalled = true;
                
                sendEvent("get_trackers_called", {
                    message: "拦截到获取Tracker URL的函数调用"
                });
            },

            onLeave: function(retval) {
                console.log("source:", this.source);
                
                sendEvent("get_trackers", {
                    message: "获取Tracker URL函数执行完成"
                });
                isGetTrackersCalled = false;
            }
        });

        // 监控设置剪贴板文本的函数
        Interceptor.attach(clipboardFuncAddr, {
            onEnter: function(args) {
                // 检查是否是从获取Tracker函数调用的
                if (isGetTrackersCalled) {
                    this.trackerText = args[1];
                    const trackerUrl = readQString(this.trackerText);
                    console.log("Tracker URL: ", trackerUrl);
                    
                    sendEvent("get_torrent_trackers_result", {
                        message: "成功获取种子文件的Tracker",
                        torrent_trackers: trackerUrl
                    });
                } 
            }
        });
    }
    
    // 启动脚本
    function initHook() {
        sendEvent("script_initialized", {
            message: "qBittorrent 获取种子Tracker监控脚本已启动"
        });
        
        // 初始化钩子
        initGetTrackerHook();
        
        sendEvent("all_hooks_installed", {
            message: "所有监控钩子安装完成，等待获取种子Tracker操作..."
        });
    }

    initHook();
})();