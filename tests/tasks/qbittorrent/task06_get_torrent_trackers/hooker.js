(function() {
    // 脚本设置 - 目标函数
    const FUNCTION_NAME_GET_TRACKERS = "_ZN17TrackerListWidget14copyTrackerUrlEv";
    const FUNCTION_NAME_SET_CLIPBOARD_TEXT = "_ZN10QClipboard7setTextERK7QStringNS_4ModeE";
    
    // Torrent类中的m_model和torrent对象的相关偏移量
    const OFFSET_TRACKERLISTWIDGET_MODEL = 0x28; // TrackerListWidget::m_model 偏移量
    const OFFSET_TRACKERLISTMODEL_TORRENT = 0x18; // TrackerListModel::m_torrent 偏移量
    
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
    
    // 从TrackerListWidget实例获取Torrent对象并读取名称
    function getTorrentNameFromWidget(widgetPtr) {
        try {
            // 从TrackerListWidget获取m_model
            const modelPtr = widgetPtr.add(OFFSET_TRACKERLISTWIDGET_MODEL).readPointer();
            if (modelPtr.isNull()) {
                console.log("modelPtr为空");
                return null;
            }

            // 从TrackerListModel获取m_torrent
            const torrentPtr = modelPtr.add(OFFSET_TRACKERLISTMODEL_TORRENT).readPointer();
            if (torrentPtr.isNull()) {
                console.log("torrentPtr为空");
                return null;
            }
            
            // 调用虚函数name()获取种子名称
            // Torrent是一个有虚函数表的类，我们需要通过虚函数表获取name方法
            const vtablePtr = torrentPtr.readPointer();
            
            // 虚函数在虚表中的偏移量(假设name()是第7个虚函数，索引为6)
            // 注意：这个偏移量可能需要调整，取决于实际的虚函数表布局
            const nameMethodIndex = 25;
            const nameMethodPtr = vtablePtr.add(nameMethodIndex * Process.pointerSize).readPointer();
            
            // 构造函数调用参数
            const nameMethod = new NativeFunction(nameMethodPtr, 'pointer', ['pointer']);
            const nameQString = nameMethod(torrentPtr);
            
            // 读取返回的QString
            return readQString(nameQString);
        } catch (e) {
            console.log("获取种子名称失败:", e);
            return null;
        }
    }
    
    // 初始化获取种子Trackers钩子函数
    function initGetTrackerHook() {
        const trackerFuncAddr = getFunctionAddress(FUNCTION_NAME_GET_TRACKERS);
        const clipboardFuncAddr = getFunctionAddress(FUNCTION_NAME_SET_CLIPBOARD_TEXT);

        let isGetTrackersCalled = false;
        let trackerWidgetPtr = null;
        
        // 监控获取Tracker的函数
        Interceptor.attach(trackerFuncAddr, {
            onEnter: function(args) {
                this.source = args[0];
                trackerWidgetPtr = args[0];
                isGetTrackersCalled = true;
                
                // 尝试获取种子名称
                const torrentName = getTorrentNameFromWidget(trackerWidgetPtr);
                if (torrentName) {
                    sendEvent("torrent_name_found", {
                        message: "成功获取种子名称",
                        torrent_name: torrentName
                    });
                    console.log("Torrent Name:", torrentName);
                } else {
                    sendEvent("error", {
                        error_type: "torrent_name_not_found",
                        message: "无法获取种子名称"
                    });
                }
                
                sendEvent("get_trackers_called", {
                    message: "拦截到获取Tracker URL的函数调用"
                });
            },

            onLeave: function(retval) {
                console.log("源对象地址:", this.source);
                
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
                    
                    // 再次尝试获取种子名称
                    const torrentName = getTorrentNameFromWidget(trackerWidgetPtr);
                    
                    sendEvent("get_torrent_trackers_result", {
                        message: "成功获取种子文件的Tracker",
                        torrent_trackers: trackerUrl,
                        torrent_name: torrentName || "未知种子"
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
