(function() {
    // 脚本设置 - 目标函数
    const FUNCTION_NAME_ADD_TORRENT = "_ZN17AddTorrentManager19addTorrentToSessionERK7QStringRKN10BitTorrent17TorrentDescriptorERKNS3_16AddTorrentParamsE";
    // SessionImpl::handleTorrentStopped 函数的符号名
    const FUNCTION_NAME_HANDLE_TORRENT_STOPPED = "_ZN10BitTorrent11SessionImpl20handleTorrentStoppedEPNS_11TorrentImplE";
    const FUNCTION_NAME_TORRENT_NAME = "_ZNK10BitTorrent7Torrent4nameEv";

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

    // 读取QString内容（直接作为对象）
    function readQStringObject(qstringObj) {
        try {
            // QString内部数据通常在对象开始后的某个偏移处
            // 尝试不同的可能布局解析QString
            
            // 1. 检查第一种常见布局：指向数据的指针在对象的开始位置
            let dataPtr = qstringObj.readPointer();
            
            // 如果指针不为空，尝试读取字符串
            if (!dataPtr.isNull()) {
                return readQStringData(dataPtr);
            }
            
            // 2. 第二种常见布局：QString有一个内联存储缓冲区
            // 尝试直接从对象中读取字符
            let str = "";
            for (let i = 8; i < 40; i += 2) { // 32字节内联缓冲区
                const c = qstringObj.add(i).readU16();
                if (c === 0) break;
                if (c >= 32 && c < 0xFFFF) { // 可打印字符
                    str += String.fromCharCode(c);
                } else {
                    break;
                }
            }
            
            if (str.length > 0) {
                return str;
            }
            
            return null;
        } catch (e) {
            sendEvent("error", {
                error_type: "qstring_read_error",
                message: `读取QString对象错误: ${e.message}`
            });
            return null;
        }
    }
    
    // 读取QString数据部分
    function readQStringData(dataPtr) {
        const MAX_CHARS = 1000;
        try {
            let str = "";
            
            for (let i = 0; i < MAX_CHARS; i++) {
                const c = dataPtr.add(i * 2).readU16();
                if (c === 0) break;
                if (c >= 32 && c < 0xFFFF) { // 可打印字符
                    str += String.fromCharCode(c);
                } else {
                    break;
                }
            }
            
            return str.length > 0 ? str : null;
        } catch (e) {
            return null;
        }
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
    
    // 直接通过名称函数地址调用
    function getTorrentName(torrentPtr) {
        try {
            // 获取name()函数的地址
            const nameFunc = getFunctionAddress(FUNCTION_NAME_TORRENT_NAME);
            if (!nameFunc) {
                return null;
            }
            
            // 创建函数包装器 - 注意return类型为QString，不是指针
            // 我们需要分配一块内存用于接收QString
            const nameFunction = new NativeFunction(nameFunc, 'void', ['pointer', 'pointer']);
            
            // 分配一块内存用于接收返回的QString
            const resultBuffer = Memory.alloc(64); // 足够存储一个QString
            
            // 调用函数，将结果放入我们的缓冲区
            nameFunction(torrentPtr, resultBuffer);
            
            // 现在resultBuffer包含了返回的QString对象
            const torrentName = readQStringObject(resultBuffer);
            
            return torrentName;
        } catch (e) {
            sendEvent("error", {
                error_type: "get_torrent_name_error",
                message: `获取种子名称错误: ${e.message}`
            });
            return null;
        }
    }
    
    // 初始化AddTorrentManager::addTorrentToSession监控钩子
    function initAddTorrentHook() {
        const funcAddr = getFunctionAddress(FUNCTION_NAME_ADD_TORRENT);
     
        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                this.source = args[0];
                console.log("source:", this.source);
                
                sendEvent("add_torrent_called", {
                    message: "拦截到添加种子到会话函数调用",
                });
            },

            onLeave: function(retval) {
                const success = retval.toInt32() !== 0;     
                const sourcePath = readQString(this.source);
               
                sendEvent("add_torrent_result", {
                    message: "添加种子到会话函数正确返回",
                    torrent_data: sourcePath 
                });
            }
        });
    }
    
    // 初始化SessionImpl::handleTorrentStopped监控钩子
    function initHandleTorrentStoppedHook() {
        const funcAddr = getFunctionAddress(FUNCTION_NAME_HANDLE_TORRENT_STOPPED);
        if (!funcAddr) return;
        
        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                this.torrentImpl = args[0];
                
                sendEvent("handle_torrent_stopped_called", {
                    message: "拦截到种子停止处理函数调用"
                });
                
                // 获取种子的名称
                const torrentName = getTorrentName(this.torrentImpl);
                
                if (torrentName) {
                    sendEvent("torrent_stopped_info", {
                        message: "成功获取停止的种子名称",
                        torrent_name: torrentName
                    });
                } else {
                    // 如果直接调用name()失败，尝试使用LogMsg的参数来获取名称
                    sendEvent("torrent_stopped_info", {
                        message: "无法获取种子名称，将尝试从LogMsg参数获取"
                    });
                }
            },
            
            onLeave: function(retval) {
                sendEvent("handle_torrent_stopped_completed", {
                    message: "种子停止处理函数执行完成"
                });
            }
        });
    }

    // 添加一个新的钩子用于拦截LogMsg函数来获取日志中的种子名称
    function initLogMsgHook() {
        // LogMsg函数的符号名，你可能需要调整
        const FUNCTION_NAME_LOG_MSG = "_ZN10BitTorrent8LogMsgVEjRK7QStringz";
        const funcAddr = getFunctionAddress(FUNCTION_NAME_LOG_MSG);
        if (!funcAddr) return;
        
        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                // LogMsg的参数中包含了格式化后的消息
                const msgPtr = args[1];
                const logMessage = readQString(msgPtr);
                
                // 检查是否是种子停止的日志
                if (logMessage && logMessage.includes("Torrent stopped")) {
                    // 尝试从消息中提取种子名称
                    const match = logMessage.match(/Torrent: "([^"]+)"/);
                    if (match && match[1]) {
                        sendEvent("torrent_stopped_log", {
                            message: "从日志消息中获取到停止的种子名称",
                            torrent_name: match[1]
                        });
                    }
                }
            }
        });
    }

    // 启动脚本
    function initHook() {
        sendEvent("script_initialized", {
            message: "qBittorrent 种子操作监控脚本已启动"
        });
        
        // 初始化钩子
        // initAddTorrentHook();
        initHandleTorrentStoppedHook();
        initLogMsgHook(); // 添加日志钩子作为备选方案
        
        sendEvent("all_hooks_installed", {
            message: "所有监控钩子安装完成，等待种子操作..."
        });
    }

    initHook();
})();