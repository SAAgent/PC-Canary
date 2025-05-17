(function() {
    // 脚本设置 - 目标函数
    const FUNCTION_NAME_SET_MAX_ACTIVE_TORRENTS = "_ZN10BitTorrent11SessionImpl24setQueueingSystemEnabledEb";
    const FUNCTION_NAME_setMaxActiveDownloads = "_ZN10BitTorrent11SessionImpl21setMaxActiveDownloadsEi";
    const FUNCTION_NAME_setMaxActiveUploads = "_ZN10BitTorrent11SessionImpl19setMaxActiveUploadsEi";
    const FUNCTION_NAME_setMaxActiveTorrents = "_ZN10BitTorrent11SessionImpl20setMaxActiveTorrentsEi";
    const OFFSET_maxActiveDownloads = 0x428;
    const OFFSET_maxActiveUploads = 0x448;
    const OFFSET_maxActiveTorrents = 0x468;

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
    
    // 初始化最大活动种子数监控钩子
    function initMaxActiveTorrentsHook() {
        const funcAddr = getFunctionAddress(FUNCTION_NAME_SET_MAX_ACTIVE_TORRENTS);
        const funcAddr_setMaxActiveDownloads = getFunctionAddress(FUNCTION_NAME_setMaxActiveDownloads);
        const funcAddr_setMaxActiveUploads = getFunctionAddress(FUNCTION_NAME_setMaxActiveUploads);
        const funcAddr_setMaxActiveTorrents = getFunctionAddress(FUNCTION_NAME_setMaxActiveTorrents);
        let isSetMaxActiveTorrentsCalled = false;
        
        // 添加函数执行计数器和定时器ID
        let functionCallCounter = 0;
        let pendingTimerId = null;
        const TIMEOUT_DELAY = 500; // 500毫秒等待时间

        let maxActiveDownloadsValue = 0;
        let maxActiveUploadsValue = 0;
        let maxActiveTorrentsValue = 0;

        // 创建最终发送事件的函数
        function sendFinalEvent() {
            sendEvent("set_max_active_torrents", {
                message: "拦截到设置最大种子数函数调用(最终结果)",
                maxActiveDownloads: maxActiveDownloadsValue,
                maxActiveUploads: maxActiveUploadsValue,
                maxActiveTorrents: maxActiveTorrentsValue   
            });
            
            // 重置状态
            isSetMaxActiveTorrentsCalled = false;
            functionCallCounter = 0;
        }

        // 每次函数执行后更新计数并考虑发送事件
        function updateFunctionCounter() {
            functionCallCounter++;
            
            // 清除之前的定时器
            if (pendingTimerId !== null) {
                clearTimeout(pendingTimerId);
            }
            
            // 设置新的定时器，确保一段时间后发送最终结果
            pendingTimerId = setTimeout(sendFinalEvent, TIMEOUT_DELAY);
        }

        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                isSetMaxActiveTorrentsCalled = true;
                this.source = args[0];
                this.setQueueingSystemEnabled = args[1];
                const setQueueingSystemEnabled = this.setQueueingSystemEnabled.toInt32() !== 0;
                console.log("setQueueingSystemEnabled:", setQueueingSystemEnabled);
                const maxActiveDownloads = this.source.add(OFFSET_maxActiveDownloads);
                const maxActiveUploads = this.source.add(OFFSET_maxActiveUploads);
                const maxActiveTorrents = this.source.add(OFFSET_maxActiveTorrents);

                maxActiveDownloadsValue = Memory.readInt(maxActiveDownloads);
                maxActiveUploadsValue = Memory.readInt(maxActiveUploads);
                maxActiveTorrentsValue = Memory.readInt(maxActiveTorrents);
                console.log("maxActiveDownloads:", maxActiveDownloadsValue);
                console.log("maxActiveUploads:", maxActiveUploadsValue);
                console.log("maxActiveTorrents:", maxActiveTorrentsValue);
                sendEvent("set_max_active_torrents", {
                    message: "拦截到设置最大种子数函数调用",
                    maxActiveDownloads: maxActiveDownloadsValue,
                    maxActiveUploads: maxActiveUploadsValue,
                    maxActiveTorrents: maxActiveTorrentsValue   
                });
            },

            onLeave: function(retval) {
                const maxActiveDownloads = this.source.add(OFFSET_maxActiveDownloads);
                const maxActiveUploads = this.source.add(OFFSET_maxActiveUploads);
                const maxActiveTorrents = this.source.add(OFFSET_maxActiveTorrents);
                maxActiveDownloadsValue = Memory.readInt(maxActiveDownloads);
                maxActiveUploadsValue = Memory.readInt(maxActiveUploads);
                maxActiveTorrentsValue = Memory.readInt(maxActiveTorrents);
                
                // 更新计数并考虑发送事件
                updateFunctionCounter();
            }
        });

        Interceptor.attach(funcAddr_setMaxActiveDownloads, {
            onEnter: function(args) {
                if (isSetMaxActiveTorrentsCalled) {
                    this.maxActiveDownloads = args[0];
                } 
            },
            onLeave: function(retval) {
                if (isSetMaxActiveTorrentsCalled) {
                    const maxActiveDownloads = this.maxActiveDownloads.add(OFFSET_maxActiveDownloads);
                    maxActiveDownloadsValue = Memory.readInt(maxActiveDownloads);
                    console.log("maxActiveDownloads:", maxActiveDownloadsValue);
                    
                    // 更新计数并考虑发送事件
                    updateFunctionCounter();
                }
            }
        });

        Interceptor.attach(funcAddr_setMaxActiveUploads, {
            onEnter: function(args) {
                if (isSetMaxActiveTorrentsCalled) {
                    this.maxActiveUploads = args[0];
                } 
            },
            onLeave: function(retval) {
                if (isSetMaxActiveTorrentsCalled) {
                    const maxActiveUploads = this.maxActiveUploads.add(OFFSET_maxActiveUploads);
                    maxActiveUploadsValue = Memory.readInt(maxActiveUploads);
                    console.log("maxActiveUploads:", maxActiveUploadsValue);
                    
                    // 更新计数并考虑发送事件
                    updateFunctionCounter();
                }
            }
        });

        Interceptor.attach(funcAddr_setMaxActiveTorrents, {
            onEnter: function(args) {
                if (isSetMaxActiveTorrentsCalled) {
                    this.maxActiveTorrents = args[0];
                } 
            },
            onLeave: function(retval) {
                if (isSetMaxActiveTorrentsCalled) {
                    const maxActiveTorrents = this.maxActiveTorrents.add(OFFSET_maxActiveTorrents);
                    maxActiveTorrentsValue = Memory.readInt(maxActiveTorrents);
                    console.log("maxActiveTorrents:", maxActiveTorrentsValue);
                    
                    // 更新计数并考虑发送事件
                    updateFunctionCounter();
                }
            }
        });
    }
    
    // 启动脚本
    function initHook() {
        sendEvent("script_initialized", {
            message: "qBittorrent 最大活动种子数监控脚本已启动"
        });
        
        // 初始化钩子
        initMaxActiveTorrentsHook();
        
        sendEvent("all_hooks_installed", {
            message: "所有监控钩子安装完成，等待设置最大活动种子数操作..."
        });
    }

    initHook();
})();