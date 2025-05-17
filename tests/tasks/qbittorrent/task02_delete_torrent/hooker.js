(function() {
    // 脚本设置 - 目标函数
    const FUNCTION_NAME_REMOVE_TORRENT = "_ZN10BitTorrent11SessionImpl13removeTorrentERKNS_9TorrentIDENS_19TorrentRemoveOptionE";
    const FUNCTION_NAME_GET_TORRENT_NAME = "_ZNK10BitTorrent11TorrentImpl4nameEv";
    const OFFSET_TO_TORRENT_NAME = 0xa8;

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

    // 读取标准C++字符串内容
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

    // 初始化删除种子监控钩子
    function initRemoveTorrentHook() {
        // 获取函数地址
        const removeTorrentAddr = getFunctionAddress(FUNCTION_NAME_REMOVE_TORRENT);
        const getTorrentNameAddr = getFunctionAddress(FUNCTION_NAME_GET_TORRENT_NAME);
        let isRemoveTorrentCalled = false;

        // 监控删除种子函数
        Interceptor.attach(removeTorrentAddr, {
            onEnter: function(args) {
                this.torrentSource = args[0];
                isRemoveTorrentCalled = true;
                sendEvent("remove_torrent_called", {
                    message: "拦截到删除种子函数调用"
                });
            },

            onLeave: function(retval) {
                console.log("Torrent source:", this.torrentSource);
                isRemoveTorrentCalled = false;
            }
        });
        
        // 监控获取种子名称函数
        Interceptor.attach(getTorrentNameAddr, {
            onEnter: function(args) {
                if (isRemoveTorrentCalled) {
                    console.log("getTorrentName called during removeTorrent");
                }
            }, 
            
            onLeave: function(retval) {
                if (isRemoveTorrentCalled) {
                    const torrentNamePtr = retval;
                    const torrentName = readQString(torrentNamePtr);
                    console.log("删除的种子名称:", torrentName);
                    
                    if (torrentName) {
                        sendEvent("remove_torrent_result", {
                            message: "成功删除种子文件",
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
            message: "qBittorrent 种子删除监控脚本已启动"
        });
        
        // 初始化钩子
        initRemoveTorrentHook();
    }

    initHook();
})();