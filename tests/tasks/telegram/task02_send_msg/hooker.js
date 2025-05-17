// Telegram消息监控钩子脚本
// 用于监听Telegram的消息发送和接收操作

(function () {

    // 脚本设置
    const MAX_CHARS = 1000; // 最大读取字符数
    // 全局变量
    const FUNCTION_NAME_SEND_MESSAGE = "_ZN7ApiWrap11sendMessageEON3Api13MessageToSendE";
    // 偏移量设置 - 根据调试确定的偏移量
    const MESSAGE_OFFSETS = {
        // 发送消息相关偏移量
        TEXT_WITH_TAGS: 0xa8, // 消息文本偏移量
        HISTORY: 0,
        PEER: 728,
        PEER_ID: 8, // peer id偏移量
        PEER_NAME: 304, // peer name偏移量
        REPLY_TO: 0x30, // 回复消息ID偏移量

        // 接收消息相关偏移量

        HISTORY_ITEM: 0x20, // HistoryItem偏移量
        FROM_ID: 0x30, // 发送者ID偏移量
        MESSAGE_TEXT: 0x50, // 消息文本偏移量
        MESSAGE_DATE: 0x38 // 消息日期偏移量
    };

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
        // 查找ApiWrap::sendMessage函数
        let sendMessageFuncAddr = Module.findExportByName(null, functionName);
        if (sendMessageFuncAddr) {
            sendEvent("function_found", {
                address: sendMessageFuncAddr.toString(),
                message: "找到函数实际地址"
            });
        } else {
            sendEvent("error", {
                error_type: "function_not_found",
                message: "无法找到函数"
            });
        }
        return sendMessageFuncAddr;
    }

    // 读取QString字符串内容
    function readQString(queryPtr, offset = 8) {
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

    // 初始化消息发送钩子
    function initSendHook() {
        // 查找发送消息函数
        const sendMessageFuncAddr = getFunctionAddress(FUNCTION_NAME_SEND_MESSAGE);
        console.log(`[+] 发送消息函数地址: ${sendMessageFuncAddr}`);
        if (!sendMessageFuncAddr) {
            return;
        }

        // 安装钩子
        Interceptor.attach(sendMessageFuncAddr, {
            onEnter: function (args) {
                try {
                    sendEvent("send_function_called", {
                        message: "拦截到消息发送函数调用"
                    });

                    // 参数分析 - 第一个参数是this，第二个参数是MessageToSend对象
                    const thisPtr = args[0];
                    const messagePtr = args[1];
                    console.log(`[+] messagePtr消息对象: ${messagePtr}`);
                    // 1. 读取消息文本
                    let messageText = null;
                    try {
                        // 尝试直接通过确定的偏移量读取
                        console.log(`[+] 消息偏移量: ${MESSAGE_OFFSETS.TEXT_WITH_TAGS}`);
                        const textPtr = messagePtr.add(MESSAGE_OFFSETS.TEXT_WITH_TAGS);
                        console.log(`[+] 消息对象: ${textPtr}`);
                        messageText = readQString(textPtr);
                        console.log(`[+] 消息内容: ${messageText}`);
                    } catch (e) {
                        console.log(`[!] 读取文本失败: ${e.message}`);
                    }

                    // 2. 读取接收者信息
                    // let peerId = 0;
                    let peerName = "";

                    try {
                        const historyPtr = messagePtr.add(MESSAGE_OFFSETS.HISTORY);
                        console.log(`[+] historyPtr 位置: ${historyPtr}`);
                        const history = historyPtr.readPointer();
                        const history_peer = history.add(MESSAGE_OFFSETS.PEER)
                        console.log(`[+] peer 位置: ${history_peer}`);
                        const peer_name_ptr = history_peer.readPointer().add(MESSAGE_OFFSETS.PEER_NAME);
                        console.log(`[+] peer_name 位置: ${peer_name_ptr}`);
                        peerName = readQString(peer_name_ptr);
                        console.log(`[+] 消息发送用户名称: "${peerName}"`);
                    } catch (e) {
                        // 忽略错误
                    }

                    // 构建消息对象
                    const messageData = {
                        type: "outgoing",
                        text: messageText || "(无法读取文本)",
                        peer: {
                            // id: peerId.toString(),
                            name: peerName
                        },
                        // reply_to: replyToId ? replyToId.toString() : null,
                        // clear_draft: clearDraft,
                        timestamp: new Date().getTime()
                    };

                    // 发送消息检测事件
                    sendEvent("message_detected", {
                        message_data: messageData,
                        message: `检测到发送消息: ${messageText?.substring(0, 50)}${messageText?.length > 50 ? '...' : ''}`
                    });

                    // 保存参数供退出时使用
                    this.messageData = messageData;
                } catch (error) {
                    sendEvent("error", {
                        error_type: "general_error",
                        message: `执行错误: ${error.message}`,
                        stack: error.stack
                    });
                }
            },

            onLeave: function (retval) {
                // 处理函数返回后的逻辑
                if (this.messageData) {
                    sendEvent("message_send_completed", {
                        message_data: this.messageData,
                        success: true
                    });
                }
            }
        });

        sendEvent("send_hook_installed", {
            message: "消息发送钩子安装完成，等待发送消息操作..."
        });

    }

    // 初始化消息接收钩子
    // function initReceiveHook() {
    // const receiveFuncAddr = findReceiveMessageFunction();
    // if (!receiveFuncAddr) {
    // return;
    // }

    // // 安装接收消息钩子

    // Interceptor.attach(receiveFuncAddr, {
    // onEnter: function(args) {

    // try {
    // sendEvent("receive_function_called", {
    // message: "拦截到消息接收函数调用"
    // });

    // // 保存参数供后续使用

    // this.historyPtr = args[0]; // HistoryItem的this指针
    // this.historyOwnerPtr = args[1]; // History*参数

    // // 如果是HistoryItem构造函数，args[2]是消息ID，args[3]是MTPDmessage

    // this.msgId = args[2];
    // this.mtpMessagePtr = args[3];
    // } catch (error) {
    // sendEvent("error", {
    // error_type: "receive_hook_error",
    // message: `接收钩子错误: ${error.message}`
    // });
    // }
    // },

    // onLeave: function(retval) {
    // try {
    // // 只有在成功处理了参数时才继续
    // if (!this.historyPtr) {
    // return;
    // }

    // // 分析消息内容
    // let fromId = 0;
    // let messageText = "";
    // let messageDate = 0;
    // try {
    // // 读取发送者ID
    // fromId = this.historyPtr.add(MESSAGE_OFFSETS.FROM_ID).readLong();

    // // 尝试读取消息文本
    // const textPtr = this.historyPtr.add(MESSAGE_OFFSETS.MESSAGE_TEXT);
    // messageText = readQString(textPtr) || "(无法读取文本)";

    // // 读取消息日期
    // messageDate = this.historyPtr.add(MESSAGE_OFFSETS.MESSAGE_DATE).readU32();
    // } catch (e) {
    // // 忽略错误
    // }



    // // 构建接收消息数据
    // const messageData = {
    // type: "incoming",
    // msg_id: this.msgId ? this.msgId.toString() : "unknown",
    // from_id: fromId.toString(),
    // text: messageText,
    // date: messageDate,
    // timestamp: new Date().getTime()
    // };

    // // 发送消息检测事件
    // sendEvent("message_detected", {
    // message_data: messageData,
    // message: `检测到接收消息: ${messageText.substring(0, 50)}${messageText.length > 50 ? '...' : ''}`
    // });
    // } catch (error) {
    // sendEvent("error", {
    // error_type: "receive_process_error",
    // message: `处理接收消息错误: ${error.message}`
    // });
    // }
    // }
    // });

    // sendEvent("receive_hook_installed", {
    // message: "消息接收钩子安装完成，等待接收消息操作..."
    // });
    // }
    // 初始化钩子

    function initHook() {

        sendEvent("script_initialized", {

            message: "Telegram消息监控脚本已启动"

        });

        // 初始化发送钩子
        initSendHook();
        // 初始化接收钩子
        // initReceiveHook();
        sendEvent("hook_installed", {
            message: "消息监控钩子安装完成，等待消息操作..."
        });
    }
    // 启动脚本
    initHook();

})();