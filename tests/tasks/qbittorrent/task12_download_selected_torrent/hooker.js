(function() {
    // 脚本设置 - 目标函数
    const FUNCTION_NAME_SET_TORRENT_PRIORITY = "_ZN19TorrentContentModel15setItemPriorityERK11QModelIndexN10BitTorrent16DownloadPriorityE";
    const FUNCTION_NAME_SET_TORRENT_PRIORITY_FILE = "_ZN23TorrentContentModelFile11setPriorityEN10BitTorrent16DownloadPriorityEb";
    const FUNCTION_NAME_PRIORITIZE_FILES = "_ZN19AddNewTorrentDialog6acceptEv"; // 监控确认文件选择的函数
    
    const OFFSET_TO_TORRENT_NAME = 0x28;
    const OFFSET_TO_TORRENT_PRIORITY = 0x50;
    const OFFSET_TO_TORRENT_INFO = 168;
    let nameArray = [];
    let priorityArray = [];
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

    // 初始化文件选择监控钩子
    function initFileSelectionHook() {
        const funcAddr = getFunctionAddress(FUNCTION_NAME_SET_TORRENT_PRIORITY);
        const setTorrentPriorityFileAddr = getFunctionAddress(FUNCTION_NAME_SET_TORRENT_PRIORITY_FILE);
        const prioritizeFilesAddr = getFunctionAddress(FUNCTION_NAME_PRIORITIZE_FILES);
        
        let isSetTorrentPriorityCalled = false;
        let selectedFiles = [];

        // 监控文件优先级设置
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

        // 监控单个文件优先级设置
        Interceptor.attach(setTorrentPriorityFileAddr, {
            onEnter: function(args) {
                // 检查是否通过UI触发
                if (isSetTorrentPriorityCalled) {
                    this.torrent = args[0];
                    this.torrent_name_addr = this.torrent.add(OFFSET_TO_TORRENT_NAME);
                    const torrent_name = readQString(this.torrent_name_addr, 8);
                    console.log("torrent_name: ", torrent_name);
                    this.torrent_priority_addr = this.torrent.add(OFFSET_TO_TORRENT_PRIORITY);

                    const torrent_priority = Memory.readInt(this.torrent_priority_addr);
                    const priority_name = DownloadPriority.getName(torrent_priority);
                    console.log("torrent_priority: ", priority_name);
                    
                    // 仅当设置为非忽略时记录文件名（表示选择下载）
                    
                    
                    sendEvent("file_selection_detected", {
                        message: "检测到文件选择操作",
                        torrent_name: torrent_name,
                        priority_name: priority_name
                    });
                }
            },
            
            onLeave: function(retval) {
                if (isSetTorrentPriorityCalled) {
                    const torrent_name_addr = this.torrent_name_addr
                const torrent_name = readQString(torrent_name_addr, 8);
                console.log("torrent_name: ", torrent_name);
                const torrent_priority_addr = this.torrent_priority_addr;
                console.log("torrent_priority_addr: ", torrent_priority_addr);
                const torrent_priority = Memory.readInt(torrent_priority_addr);
                const priority_name = DownloadPriority.getName(torrent_priority);

                if (torrent_priority !== DownloadPriority.Ignored) {
                        selectedFiles.push(torrent_name);
                    
                }
                sendEvent("file_selection_finished", {
                    message: "检测到文件选择操作结束",
                    torrent_name: torrent_name,
                    priority_name: priority_name
                });
            }
        }});

        // 监控确认文件选择的函数
        Interceptor.attach(prioritizeFilesAddr, {
            onEnter: function(args) {
                // 获取torrent对象和文件优先级列表
                this.torrentImpl = args[0];
                this.prioritiesList = args[1];
                
      
                const torrentName = readStdString(this.torrentImpl.add(OFFSET_TO_TORRENT_INFO));
                
                console.log("确认文件选择 - 种子:", torrentName);
                console.log("已选择文件数量:", selectedFiles.length);
                
                // 报告文件下载已开始
                sendEvent("file_download_started", {
                    message: "文件开始下载",
                    selected_files: selectedFiles
                });
                
                
            },
            
            onLeave: function(retval) {
                // 无需额外处理
            }
        });
    }

    // 启动脚本
    function initHook() {
        sendEvent("script_initialized", {
            message: "qBittorrent 选择性下载监控脚本已启动"
        });
        
        // 初始化钩子
        initFileSelectionHook();
        
        sendEvent("all_hooks_installed", {
            message: "所有监控钩子安装完成，等待选择文件操作..."
        });
    }

    initHook();
})();