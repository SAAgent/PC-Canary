(function() {
    // 脚本设置 - 目标函数
    const FUNCTION_NAME_SET_PROXY_CONFIGURATION = "_ZN3Net25ProxyConfigurationManager21setProxyConfigurationERKNS_18ProxyConfigurationE";
    const OFFSET_TO_PROXY_TYPE = 0x10;
    const OFFSET_TO_PROXY_HOST = 0x18;
    const OFFSET_TO_PROXY_PORT = 0x30;
    // const OFFSET_TO_PROXY_USER = 0x28;
    // const OFFSET_TO_PROXY_PASS = 0x30;
    
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
    
    // 读取代理类型
    function readProxyType(proxyTypePtr) {
        try {
            // 读取int32值（假设枚举是32位整数）
            const proxyTypeInt = proxyTypePtr.readInt();
            console.log("proxyTypeInt:", proxyTypeInt);
            // 根据枚举定义解释值
            let proxyTypeName;
            switch (proxyTypeInt) {
                case 0:
                    proxyTypeName = "None";
                    break;
                case 1:
                    proxyTypeName = "HTTP";
                    break;
                case 2:
                    proxyTypeName = "SOCKS5";
                    break;
                case 5:
                    proxyTypeName = "SOCKS4";
                    break;
                default:
                    proxyTypeName = "未知类型";
            }
            
            return proxyTypeName;
        } catch (e) {
            console.log("读取代理类型错误:", e);
            sendEvent("error", {
                error_type: "proxy_type_read_error",
                message: `读取代理类型错误: ${e.message}`
            });
            return null;
        }
    }

    // 初始化代理设置监控钩子
    function initProxyConfigHook() {
        const funcAddr = getFunctionAddress(FUNCTION_NAME_SET_PROXY_CONFIGURATION);
     
        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                this.source = args[0];
                this.proxy_type = this.source.add(OFFSET_TO_PROXY_TYPE);  
                this.proxy_host = this.source.add(OFFSET_TO_PROXY_HOST);
                this.proxy_port = this.source.add(OFFSET_TO_PROXY_PORT);

                const proxy_host_str = readQString(this.proxy_host);
                const proxy_port_str = this.proxy_port.readU16();
                const proxy_type_str = readProxyType(this.proxy_type);
          
                console.log("proxy_type:", proxy_type_str);
                console.log("proxy_host:", proxy_host_str);
                console.log("proxy_port:", proxy_port_str);
                
                sendEvent("agent_connect_called", {
                    message: "连接代理",
                    proxy_type: proxy_type_str,
                    proxy_host: proxy_host_str,
                    proxy_port: proxy_port_str
                });
            },

            onLeave: function(retval) {
                const proxy_host_str = readQString(this.proxy_host);
                const proxy_port_str = this.proxy_port.readU16();
                const proxy_type_str = readProxyType(this.proxy_type);
                
                console.log("proxy_type:", proxy_type_str);
                console.log("proxy_host:", proxy_host_str);
                console.log("proxy_port:", proxy_port_str);
               
                sendEvent("agent_connect_result", {
                    message: "连接代理成功",
                    proxy_type: proxy_type_str,
                    proxy_host: proxy_host_str,
                    proxy_port: proxy_port_str
                });
            }
        });
    }
    
    // 启动脚本
    function initHook() {
        sendEvent("script_initialized", {
            message: "qBittorrent 代理设置监控脚本已启动"
        });
        
        // 初始化钩子
        initProxyConfigHook();
        
        sendEvent("all_hooks_installed", {
            message: "所有监控钩子安装完成，等待设置代理操作..."
        });
    }

    initHook();
})();