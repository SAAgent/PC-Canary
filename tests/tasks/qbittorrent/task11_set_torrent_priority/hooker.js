(function() {
    // 脚本设置 - 目标函数
    const FUNCTION_NAME_SET_TORRENT_PRIORITY="_ZN19TorrentContentModel15setItemPriorityERK11QModelIndexN10BitTorrent16DownloadPriorityE";
    const FUNCTION_NAME_SET_TORRENT_PRIORITY_FILE="_ZN23TorrentContentModelFile11setPriorityEN10BitTorrent16DownloadPriorityEb"
    const OFFSET_TO_TORRENT_NAME=0x28
    const OFFSET_TO_TORRENT_PRIORITY=0x50
    // const OFFSET_TO_TORRENT_STOP=0x530
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
            
         
    
    const DownloadPriority = {
        Ignored: 0,
        Normal: 1,
        High: 6,
        Maximum: 7,
        Mixed: -1, // Frida 会正确读取 -1
        getName: function(value) {
            for (const key in this) {
                if (this.hasOwnProperty(key) && typeof this[key] === 'number' && this[key] === value) {
                    return key;
                }
            }
            return "Unknown";
        }
    };
    
    function readQStringFromPtr(strPtr, offset = 0) {
        const MAX_CHARS = 2000; // 增加最大字符数以适应长文件名
        try {
            const actualPtr = strPtr.add(offset);
            
            if (actualPtr.isNull()) {
                return null;
            }
            
            // 读取 UTF-16 字符串
            let str = "";
            
            for (let i = 0; i < MAX_CHARS; i++) {
                try {
                    const c = actualPtr.add(i * 2).readU16();
                    
                    // 允许所有可打印字符和常见控制字符
                    if (c === 0) { // 字符串结束
                        break;
                    } else {
                        // 直接添加所有字符，包括控制字符
                        str += String.fromCharCode(c);
                    }
                } catch (e) {
                    console.log("读取字符时出错:", e);
                    break;
                }
            }
            
            return str.length > 0 ? str : null;
        } catch (e) {
            console.log(`读取内存错误: ${e.message}`);
            return null;
        }
    }

    // 初始化AddTorrentManager::addTorrentToSession监控钩子
    function initStopAllTorrentHook() {
        const funcAddr = getFunctionAddress(FUNCTION_NAME_SET_TORRENT_PRIORITY);
        const setTorrentPriorityFileAddr=getFunctionAddress(FUNCTION_NAME_SET_TORRENT_PRIORITY_FILE)

        let isSetTorrentPriorityCalled = false;
        

        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                this.source = args[0];
                isSetTorrentPriorityCalled = true;
            },

            onLeave: function(retval) {
                console.log("source:", this.source);
                
                
                
                isSetTorrentPriorityCalled = false;
            }
        });

        // Hook torrent->stop()
        Interceptor.attach(setTorrentPriorityFileAddr, {
            onEnter: function(args) {
            // Check if stopVisibleTorrents was called before this
                if (isSetTorrentPriorityCalled) {
                    this.torent= args[0]
                    const torrent_name_addr1=this.torent.add(OFFSET_TO_TORRENT_NAME)
                    const torrent_name_addr=torrent_name_addr1
                    const torrent_name=readQString(torrent_name_addr, 8)
                    console.log("torrent_name: ", torrent_name);
                    const torrent_priority_addr=this.torent.add(OFFSET_TO_TORRENT_PRIORITY)

                    const torrent_priority=Memory.readInt(torrent_priority_addr)
                    const priority_name=DownloadPriority.getName(torrent_priority)
                    console.log("torrent_priority: ", priority_name);
                    sendEvent("set_torrent_priority_before", {
                        message: "拦截到设置种子文件优先级函数",
                        torrent_name: torrent_name,
                        torrent_priority: priority_name
                    });
                // console.log("  Arguments:", args);
            } 
            },
            onLeave: function(retval) {
            // Optionally log when torrent->stop() finishes
                if (isSetTorrentPriorityCalled) {
                    const torrent_name_addr=this.torent.add(OFFSET_TO_TORRENT_NAME)
                    const torrent_name=readQString(torrent_name_addr)
                    console.log("torrent_name: ", torrent_name);
                    const torrent_priority_addr=this.torent.add(OFFSET_TO_TORRENT_PRIORITY)

                    const torrent_priority=Memory.readInt(torrent_priority_addr)
                    const priority_name=DownloadPriority.getName(torrent_priority)
                    console.log("torrent_priority: ", priority_name);
                    sendEvent("set_torrent_priority_after", {
                        message: "成功设置种子文件优先级",
                        torrent_name: torrent_name,
                        torrent_priority: priority_name
                    });
              
            //   // console.log("  Return Value:", retval);
            
            }
                
        }});
    
    
    }
    


    // 启动脚本
    function initHook() {
        sendEvent("script_initialized", {
            message: "qBittorrent 种子添加监控脚本已启动"
        });
        

        // 初始化钩子
        initStopAllTorrentHook();
        
        sendEvent("all_hooks_installed", {
            message: "所有监控钩子安装完成，等待添加种子操作..."
        });
    }

    initHook();
})();