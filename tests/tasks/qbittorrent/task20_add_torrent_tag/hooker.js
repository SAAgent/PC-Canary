(function() {
    // 脚本设置 - 目标函数
    const FUNCTION_NAME_ADD_TAG = "_ZN10BitTorrent11TorrentImpl6addTagERK3Tag";
    const OFFSET_TAG_NAME = 0xa8;
    
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
    
    // 读取标准C++字符串
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
  
    // 初始化添加标签监控钩子
    function initAddTagHook() {
        const funcAddr = getFunctionAddress(FUNCTION_NAME_ADD_TAG);
     
        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                this.torrent = args[0];
                const torrent_name = this.torrent.add(OFFSET_TAG_NAME);
                const torrent_name_str = readStdString(torrent_name);
                this.tag_name = args[1];
                
                console.log("torrent_name:", torrent_name_str);
                const tag_name_str = readQString(this.tag_name);
                console.log("tag_name:", tag_name_str);
                
                sendEvent("add_tag_called", {
                    message: "拦截到添加标签函数调用",
                    torrent_name: torrent_name_str,
                    tag_name: tag_name_str
                });
            },

            onLeave: function(retval) {
                const tag_name = readQString(this.tag_name);
                console.log("tag_name:", tag_name);
                const addTagResult = retval.toInt32() !== 0;
                console.log("retval:", retval);
                console.log("add_Tag:", addTagResult);   
                sendEvent("add_tag_result", {
                    message: "为种子添加标签成功",
                    torrent_data: tag_name 
                });
            }
        });
    }

    // 启动脚本
    function initHook() {
        sendEvent("script_initialized", {
            message: "qBittorrent 添加标签监控脚本已启动"
        });
        
        // 初始化钩子
        initAddTagHook();
        
        sendEvent("all_hooks_installed", {
            message: "所有监控钩子安装完成，等待添加标签操作..."
        });
    }

    initHook();
})();