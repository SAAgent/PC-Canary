(function() {
    // 脚本设置 - 目标函数
    const FUNCTION_NAME_addTrackers = "_ZN10BitTorrent11TorrentImpl11addTrackersE5QListINS_12TrackerEntryEE";
    const FUNCTION_ADDRESS_makeTrackerEntry = "0x6f7f78"; // 从nm命令得到的地址
    const OFFSET_TO_TORRENT_NAME = 0xa8

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

    // 获取静态函数地址（使用基址+偏移量）
    function getStaticFunctionAddress(offsetAddress) {
        try {
            // 获取qbittorrent主模块基址
            const mainModule = Process.getModuleByName("qbittorrent");
            if (!mainModule) {
                sendEvent("error", {
                    error_type: "module_not_found",
                    message: "无法找到qbittorrent主模块"
                });
                return null;
            }
            
            // 将偏移量转换为数字并计算实际地址
            const offset = parseInt(offsetAddress, 16);
            const actualAddress = mainModule.base.add(offset);
            
            sendEvent("function_found", {
                function_name: "makeNativeAnnounceEntry (static)",
                address: actualAddress.toString(),
                message: `找到静态函数的实际地址，基址: ${mainModule.base}, 偏移: ${offsetAddress}`
            });
            
            return actualAddress;
        } catch (e) {
            sendEvent("error", {
                error_type: "address_calculation_error",
                message: `计算静态函数地址错误: ${e.message}`
            });
            return null;
        }
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
    
    // 初始化添加Tracker监控钩子
    function initAddTrackersHook() {
        const funcAddr = getFunctionAddress(FUNCTION_NAME_addTrackers);
        const makeTrackerEntryAddr = getStaticFunctionAddress(FUNCTION_ADDRESS_makeTrackerEntry);
        let isAddTrackersCalled = false;

        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                isAddTrackersCalled = true;
                this.source = args[0];
                this.torrent_name = this.source.add(OFFSET_TO_TORRENT_NAME);
                const torrent_name = readStdString(this.torrent_name);
         
                console.log("torrent_name:", torrent_name);
            
                sendEvent("add_torrent_url_called", {
                    message: "拦截到增加tracker函数调用",
                    torrent_name: torrent_name
                });
            },

            onLeave: function(retval) {
                isAddTrackersCalled = false;
            }
        });

        // 确保找到了makeTrackerEntryAddr再尝试attach
        if (makeTrackerEntryAddr) {
            Interceptor.attach(makeTrackerEntryAddr, {
                onEnter: function(args) {
                    // Check if stopVisibleTorrents was called before this
                    if (isAddTrackersCalled) {
                        this.tracker_url = args[1];
                        
                        console.log("[+] makeTrackerEntry called from within addTrackers!");
                        // You can inspect arguments (like the 'this' pointer for the torrent object)
                    } 
                },
                onLeave: function(retval) {
                    // Optionally log when torrent->stop() finishes
                    if (isAddTrackersCalled) {
                        this.tracker_url_str = readQString(this.tracker_url);
                        console.log("  tracker_url:", this.tracker_url_str);
                        sendEvent("add_tracker_url_result", {
                            message: "增加tracker成功",
                            tracker_url: this.tracker_url_str
                        });
                    }   
                }
            });
        } else {
            sendEvent("error", {
                error_type: "hook_failed",
                message: "无法为makeNativeAnnounceEntry函数设置钩子，因为找不到函数地址"
            });
        }
    }
    
    // 启动脚本
    function initHook() {
        sendEvent("script_initialized", {
            message: "qBittorrent 添加Tracker监控脚本已启动"
        });
        
        // 初始化钩子
        initAddTrackersHook();
        
        sendEvent("all_hooks_installed", {
            message: "所有监控钩子安装完成，等待添加Tracker操作..."
        });
    }

    initHook();
})();