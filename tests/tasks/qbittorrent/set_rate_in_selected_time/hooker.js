(function() {
    // 脚本设置 - 目标函数
    const FUNCTION_NAME_IS_TIME_FOR_ALTERNATIVE = "_ZNK18BandwidthScheduler20isTimeForAlternativeEv";
    const FUNCTION_NAME_GET_START_TIME="_ZNK11Preferences21getSchedulerStartTimeEv"
    const FUNCTION_NAME_GET_END_TIME="_ZNK11Preferences19getSchedulerEndTimeEv"
    const OFFSET_TO_TORRENT_INFO_NAME=0xa8
    const OFFSET_TO_TORRENT_STOP=0x530
    let statusArray = [];

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
    
    function checkAllSuccess() {
        return statusArray.every(status => status === 0);
    }
    

    // 读取QTime对象中的mds成员 - 基于调试结果优化
    function readQTimeMds(qtimePtr) {
        try {
            // 检查指针有效性
            if (!qtimePtr || qtimePtr.isNull()) {
                console.log("QTime指针无效");
                return null;
            }
            
            // 根据调试结果，QTime对象的mds成员直接位于对象起始位置（偏移量=0）
            // 因此可以直接读取该地址的int值
            const mdsValue = qtimePtr.readInt();
            console.log("直接读取的mdsValue:", mdsValue);
            
            // 将mds毫秒值转换为时间
            const hours = Math.floor(mdsValue / 3600000);
            const minutes = Math.floor((mdsValue % 3600000) / 60000);
            const seconds = Math.floor((mdsValue % 60000) / 1000);
            const msecs = mdsValue % 1000;
            
            return {
                mdsValue: mdsValue,
                hours: hours,
                minutes: minutes,
                seconds: seconds,
                msecs: msecs,
                timeString: `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}.${msecs.toString().padStart(3, '0')}`
            };
        } catch (e) {
            console.log("读取QTime.mds错误:", e, e.stack);
            sendEvent("error", {
                error_type: "qtime_read_error",
                message: `读取QTime.mds错误: ${e.message}`
            });
            return null;
        }
    }

    // 用于检查内存映射的辅助函数
    function checkMemoryAccess(address) {
        try {
            console.log(`检查地址: ${address}`);
            
            // 尝试将地址转换为NativePointer（如果它不是）
            const ptr = (typeof address === 'object') ? address : ptr(address);
            console.log(`转换后的指针: ${ptr}`);
            
            // 检查内存访问权限
            const accessInfo = {
                readable: false,
                writable: false,
                executable: false
            };
            
            try {
                // 尝试读取1字节，测试可读性
                Memory.readU8(ptr);
                accessInfo.readable = true;
            } catch (e) {
                console.log(`不可读: ${e.message}`);
            }
            
            try {
                // 尝试写入后再恢复，测试可写性（谨慎使用）
                const originalByte = Memory.readU8(ptr);
                Memory.writeU8(ptr, originalByte);
                accessInfo.writable = true;
            } catch (e) {
                console.log(`不可写: ${e.message}`);
            }
            
            try {
                // 检查是否位于可执行代码区域
                const ranges = Process.enumerateRanges('--x');
                for (const range of ranges) {
                    if (ptr.compare(range.base) >= 0 && 
                        ptr.compare(range.base.add(range.size)) < 0) {
                        accessInfo.executable = true;
                        break;
                    }
                }
            } catch (e) {
                console.log(`检查可执行权限错误: ${e.message}`);
            }
            
            console.log(`内存访问权限: 可读=${accessInfo.readable}, 可写=${accessInfo.writable}, 可执行=${accessInfo.executable}`);
            
            return accessInfo;
        } catch (e) {
            console.log(`检查内存访问时出错: ${e.message}`);
            return null;
        }
    }

    // 尝试读取QTime对象的不同方法
    function tryReadQTime(qtimePtr) {
        console.log(`===== 尝试读取QTime对象 (地址: ${qtimePtr}) =====`);
        
        const results = {};
        
        // 检查内存访问权限
        console.log("1. 检查内存映射和访问权限");
        const accessInfo = checkMemoryAccess(qtimePtr);
        
        // 如果可读，尝试读取前32字节的十六进制转储
        if (accessInfo && accessInfo.readable) {
            console.log("2. 读取内存内容的十六进制转储:");
            try {
                const bytes = [];
                for (let i = 0; i < 32; i++) {
                    bytes.push(Memory.readU8(qtimePtr.add(i)).toString(16).padStart(2, '0'));
                }
                console.log(`前32字节: ${bytes.join(' ')}`);
                results.memoryDump = bytes.join(' ');
            } catch (e) {
                console.log(`内存转储失败: ${e.message}`);
            }
        }
        
        // 尝试不同的读取方法
        console.log("3. 尝试不同的读取方法:");
        
        // 方法1: 直接读取int (偏移量=0)
        try {
            const value = qtimePtr.readInt();
            console.log(`方法1 (直接readInt): ${value}`);
            results.method1 = value;
        } catch (e) {
            console.log(`方法1失败: ${e.message}`);
        }
        
        // 方法2: 读取偏移量4处的int
        try {
            const value = qtimePtr.add(4).readInt();
            console.log(`方法2 (偏移量4): ${value}`);
            results.method2 = value;
        } catch (e) {
            console.log(`方法2失败: ${e.message}`);
        }
        
        // 方法3: 尝试读取指针然后读取int
        try {
            const derefPtr = qtimePtr.readPointer();
            console.log(`解引用后的指针: ${derefPtr}`);
            const value = derefPtr.readInt();
            console.log(`方法3 (指针然后readInt): ${value}`);
            results.method3 = value;
        } catch (e) {
            console.log(`方法3失败: ${e.message}`);
        }
        
        return results;
    }

    // 用eax寄存器截获函数返回值的helper函数
    function captureReturnValue(targetFunction, callbacks) {
        // 确保callbacks对象存在并有默认值
        callbacks = callbacks || {};
        const onEnter = callbacks.onEnter || function() {};
        
        console.log(`为函数 ${targetFunction} 设置返回值捕获`);
        
        // 创建一个Interceptor
        Interceptor.attach(targetFunction, {
            onEnter: function(args) {
                // 保存this指针和参数，以便传递给回调
                this.args = args;
                // 调用用户提供的onEnter回调
                onEnter.call(this, args);
            },
            
            onLeave: function(retval) {
                try {
                    // 在x86_64架构上，函数返回值通常存储在eax/rax寄存器中
                    // 对于4字节整数值(如QTime中的mds)，使用eax就足够了
                    const context = this.context;
                    
                    if (context) {
                        // 读取eax寄存器的值(4字节整数)
                        const eaxValue = context.eax;
                        console.log(`函数返回，eax寄存器值: ${eaxValue}`);
                        
                        // 对于QTime，我们可以假设eax包含了mds值
                        // 这是基于一个假设：QTime的返回值如果是通过寄存器传递，mds值会在eax中
                        
                        // 将毫秒转换为时间
                        const hours = Math.floor(eaxValue / 3600000);
                        const minutes = Math.floor((eaxValue % 3600000) / 60000);
                        const seconds = Math.floor((eaxValue % 60000) / 1000);
                        const msecs = eaxValue % 1000;
                        
                        const timeString = `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}.${msecs.toString().padStart(3, '0')}`;
                        console.log(`转换为时间: ${timeString}`);
                        
                        // 如果提供了回调函数，传递结果
                        if (typeof callbacks.onRegisterCapture === 'function') {
                            callbacks.onRegisterCapture.call(this, eaxValue, {
                                hours, minutes, seconds, msecs, timeString
                            });
                        }
                        
                        // 我们不修改返回值，只是读取它
                        return retval;
                    } else {
                        console.log("无法获取CPU上下文");
                        if (typeof callbacks.onError === 'function') {
                            callbacks.onError.call(this, new Error("无法获取CPU上下文"));
                        }
                        return retval;
                    }
                } catch (error) {
                    console.log("读取寄存器值时出错:", error);
                    if (typeof callbacks.onError === 'function') {
                        callbacks.onError.call(this, error);
                    }
                    return retval;
                }
            }
        });
    }

    // 初始化AddTorrentManager::addTorrentToSession监控钩子
    function initStopAllTorrentHook() {
        const funcAddr = getFunctionAddress(FUNCTION_NAME_IS_TIME_FOR_ALTERNATIVE);
        const start_time = getFunctionAddress(FUNCTION_NAME_GET_START_TIME);
        const end_time = getFunctionAddress(FUNCTION_NAME_GET_END_TIME);
        let isTimeForAlternative = false;

        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                this.source = args[0];
                isTimeForAlternative = true;
            },

            onLeave: function(retval) {
                console.log("source:", this.source);
                
                sendEvent("set_ratelimit_in_selected_time", {
                    message: "成功设置限速时间"
                });
                isTimeForAlternative = false;
            }
        });

        // Hook start_time - 使用寄存器捕获
        captureReturnValue(start_time, {
            onEnter: function(args) {
                if (isTimeForAlternative) {
                    console.log("start_time function called");
                    this.captureNow = true;
                }
            },
            onRegisterCapture: function(mdsValue, timeInfo) {
                if (this.captureNow) {
                    console.log("捕获到开始时间的mds值:", mdsValue);
                    console.log("格式化的开始时间:", timeInfo.timeString);
                    
                    sendEvent("set_ratelimit_in_selected_time_success", {
                        message: "成功获取限速开始时间",
                        start_time_mds: mdsValue,
                        start_time_formatted: timeInfo.timeString
                    });
                }
            },
            onError: function(error) {
                console.log("捕获开始时间时出错:", error);
                sendEvent("error", {
                    error_type: "start_time_capture_error",
                    message: `捕获开始时间时出错: ${error.message}`
                });
            }
        });

        // Hook end_time - 使用寄存器捕获
        captureReturnValue(end_time, {
            onEnter: function(args) {
                if (isTimeForAlternative) {
                    console.log("end_time function called");
                    this.captureNow = true;
                }
            },
            onRegisterCapture: function(mdsValue, timeInfo) {
                if (this.captureNow) {
                    console.log("捕获到结束时间的mds值:", mdsValue);
                    console.log("格式化的结束时间:", timeInfo.timeString);
                    
                    sendEvent("set_ratelimit_in_selected_time_success", {
                        message: "成功获取限速结束时间",
                        end_time_mds: mdsValue,
                        end_time_formatted: timeInfo.timeString
                    });
                }
            },
            onError: function(error) {
                console.log("捕获结束时间时出错:", error);
                sendEvent("error", {
                    error_type: "end_time_capture_error",
                    message: `捕获结束时间时出错: ${error.message}`
                });
            }
        });
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