(function() {
    // 脚本设置 - 目标函数
    const FUNCTION_NAME_REMOVE_TORRENT = "_ZN10BitTorrent11SessionImpl13removeTorrentERKNS_9TorrentIDENS_19TorrentRemoveOptionE";
    const FUNCTION_NAME_GET_TORRENT_NAME="_ZNK10BitTorrent11TorrentImpl4nameEv"
    const OFFSET_TO_TORRENT_NAME=0xa8
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

   // ... existing code ...


    

    // 初始化AddTorrentManager::addTorrentToSession监控钩子
    function initRemoveTorrentHook() {

        // 获取函数地址
        const removeTorrentAddr = getFunctionAddress(FUNCTION_NAME_REMOVE_TORRENT);
        const torrentImplConstructorAddr = getFunctionAddress(FUNCTION_NAME_GET_TORRENT_NAME);
        let isRemoveTorrentCalled = false;

        Interceptor.attach(removeTorrentAddr, {
            onEnter: function(args) {
                this.source = args[0];
                isRemoveTorrentCalled = true;
            },

            onLeave: function(retval) {
                console.log("source:", this.source);
                
                
                
                isRemoveTorrentCalled = false;
            }
        });
        // Hook torrent->stop()
        
        Interceptor.attach(torrentImplConstructorAddr, {
           
                onEnter: function(args) {
                // Check if stopVisibleTorrents was called before this
                if (isRemoveTorrentCalled) {
                        this.torent= args[0]
                        const torrent_name_addr=this.torent.add(OFFSET_TO_TORRENT_NAME)
                        const torrent_name=readStdString(torrent_name_addr)
                        console.log("torrent_name: ", torrent_name)
                        // console.log("[+] torrent->name() called from within stopVisibleTorrents!");
                        // // You can inspect arguments (like the 'this' pointer for the torrent object)
                        // console.log("  Torrent Object:", this);
                    // console.log("  Arguments:", args);
                }
            }, 
            
            onLeave: function(retval) {
            // Optionally log when torrent->stop() finishes
                if (isRemoveTorrentCalled) {
                    // const torrent_name=this.torent.add(OFFSET_TO_TORRENT_NAME)
                    const torrent_name= retval[1]

                    const name = readQString(torrent_name)
                    console.log("torrent name: ", name)
                    const torrent_name_addr=this.torent.add(OFFSET_TO_TORRENT_NAME)
                    const torrent_name1=readQString(torrent_name_addr)
                    console.log("torrent_name: ", torrent_name1)
                    // console.log("[+] torrent->name() finished.");
                    // sendEvent("delete_torrent", {
                    //     message: "成功删除种子文件",
                    //     torrent_name: name
                    // });
                }
            //   // console.log("  Return Value:", retval);
            
            },
                
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