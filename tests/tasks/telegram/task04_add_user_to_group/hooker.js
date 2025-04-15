// Telegram添加用户到群组监控钩子脚本

// 用于监听Telegram的添加用户到群组操作



(function () {

    // 脚本设置
    const FUNCTION_NAME_ApplyChatUpdate = "_ZN4Data15ApplyChatUpdateEN3gsl8not_nullIP8ChatDataEERKN2tl5boxedI19MTPchatParticipantsEE";
    const FUNCTION_NAME_size = "_ZNK4base14flat_multi_setIN3gsl8not_nullIP8UserDataEESt4lessIvEE4sizeEv";
    const OFFSET_participants_to_chatdata = 456
    const OFFSET_name_to_chatdata = 304
    const OFFSET_name_to_participant = 304

    // 向评估系统发送事件

    function sendEvent(eventType, data = {}) {
        const payload = {
            event: eventType,
            ...data,
            timestamp: new Date().getTime()
        };
        send(payload);

    }



    function getFunctionAddress(functionName) {
        // 查找函数地址
        let funcAddr = Module.findExportByName(null, functionName);
        if (funcAddr) {
            sendEvent("function_found", {
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



    // 初始化群组信息更新钩子

    function initApplyChatUpdateHook() {

        const applyChatUpdateFuncAddr = getFunctionAddress(FUNCTION_NAME_ApplyChatUpdate);
        if (!applyChatUpdateFuncAddr) {
            return;
        }

        Interceptor.attach(applyChatUpdateFuncAddr, {
            onEnter: function (args) {
                sendEvent("apply_chat_update_called", {
                    message: "拦截到本地群组状态更新函数调用"
                });
                this.chatData = args[0]
                console.log("chatData Address: ", this.chatData)
            },

            onLeave: function (retval) {
                sendEvent("apply_chat_update_returned", {
                    message: "本地群组状态更新函数正确返回"
                });
                console.log("chatData Address: ", this.chatData)
                const chat_name = readQString(this.chatData.add(OFFSET_name_to_chatdata))
                console.log("chat_name: ", chat_name)
                const participants_addr = this.chatData.add(OFFSET_participants_to_chatdata)
                let participantCount = 0 // 获取size函数的地址
                const sizeFuncAddr = getFunctionAddress(FUNCTION_NAME_size);
                if (sizeFuncAddr) {
                    // 创建NativeFunction来调用size函数
                    const sizeFunc = new NativeFunction(sizeFuncAddr, 'size_t', ['pointer']);
                    participantCount = sizeFunc(participants_addr);
                    sendEvent("participants_count", {
                        count: participantCount,
                        message: `群组 ${chat_name} 当前有 ${participantCount} 个成员`
                    });
                }

                let participants = []
                const participant_0_ptr = participants_addr.readPointer()
                for (let i = 0; i < participantCount; i++) {
                    const participant_i_ptr = participant_0_ptr.add(i * 0x8)
                    console.log("participant_i_ptr: ", participant_i_ptr)
                    const participant_i = participant_i_ptr.readPointer()
                    console.log("participant_i: ", participant_i)
                    const participant_i_name = readQString(participant_i.add(OFFSET_name_to_participant))
                    console.log("participant_", i, ": ", participant_i_name)
                    participants.push(participant_i_name)
                }

                sendEvent("chatinfo_updated", {
                    chat_name: chat_name,
                    participants: participants
                });
            }
        });
    }



    // 初始化钩子

    function initHook() {
        sendEvent("script_initialized", {
            message: "Telegram添加用户到群组监控脚本已启动"
        });

        // 初始化各个钩子
        initApplyChatUpdateHook();
        sendEvent("hook_installed", {
            message: "添加用户到群组监控钩子安装完成，等待操作..."
        });
    }

    // 启动脚本
    initHook();

})();