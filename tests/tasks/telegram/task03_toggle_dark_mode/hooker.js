// Telegram暗黑模式切换监控钩子脚本
// 用于监听Telegram的暗黑模式切换操作

(function () {
    // 脚本设置
    const FUNCTION_NAME_IsNightMode = "_ZN6Window5Theme11IsNightModeEv";
    const FUNCTION_NAME_writeSettings = "_ZN5Local13writeSettingsEv";
    const FUNCTION_NAME_WRITE_ENCRYPTED = "_ZN7Storage7details19FileWriteDescriptor14writeEncryptedERNS0_19EncryptedDescriptorERKSt10shared_ptrIN3MTP7AuthKeyEE";

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

    // 主动调用IsNightMode函数并检查返回值
    function checkNightModeStatus() {
        const isNightModeFuncAddr = getFunctionAddress(FUNCTION_NAME_IsNightMode);
        if (!isNightModeFuncAddr) {
            return;
        }

        // 使用NativeFunction调用
        const isNightMode = new NativeFunction(isNightModeFuncAddr, 'bool', [])();
        console.log("当前夜间模式状态:", isNightMode);

        // 发送事件通知
        sendEvent("night_mode_status_checked", {
            message: "主动检查夜间模式状态",
            isNightMode: isNightMode
        });
        return isNightMode;
    }

    // 初始化主题写入钩子
    function initWriteSettingsHook() {
        const writeSettingsFuncAddr = getFunctionAddress(FUNCTION_NAME_writeSettings);
        if (!writeSettingsFuncAddr) {
            return;
        }

        Interceptor.attach(writeSettingsFuncAddr, {
            onEnter: function (args) {
                sendEvent("write_settings_called", {
                    message: "拦截到设置项会更新"
                });

                // 检查此时是否已经进入暗黑模式
                const isNightMode = checkNightModeStatus();

                sendEvent("night_mode_setting_detected", {
                    message: "当前设置的系统主题模式为：" + (isNightMode ? "暗黑" : "明亮"),
                    isNightMode: isNightMode
                });
    
                const targetAddress = writeSettingsFuncAddr.add(0x610F4E6)
                const targetValue = targetAddress.readU8()
                console.log("Var: _settingsWriteAllowed", targetValue)
                if (targetValue) {
                    sendEvent("settings_write_allowed", {
                        message: "检测到_settingsWriteAllowed为true，设置项会被保存"
                    });
                }
            },

            onLeave: function (retval) {
                sendEvent("write_settings_returned", {
                    message: "写入设置函数正确返回"
                });
            }
        });

    }

    // 初始化加密写入钩子
    // function initWriteEncryptedHook() {
    // const writeEncryptedFuncAddr = getFunctionAddress(FUNCTION_NAME_WRITE_ENCRYPTED);
    // if (!writeEncryptedFuncAddr) {
    // return;
    // }

    // Interceptor.attach(writeEncryptedFuncAddr, {
    // onEnter: function (args) {
    // sendEvent("write_encrypted_called", {
    // message: "拦截到加密写入函数调用"
    // });
    // }
    // });

    // sendEvent("write_encrypted_hook_installed", {
    // message: "加密写入钩子安装完成，等待加密写入操作..."
    // });
    // }

    // 初始化钩子
    function initHook() {
        sendEvent("script_initialized", {
            message: "Telegram暗黑模式监控脚本已启动"
        });

        // 初始化各个钩子
        checkNightModeStatus()
        initWriteSettingsHook();
        // initWriteEncryptedHook();
        sendEvent("hook_installed", {
            message: "暗黑模式监控钩子安装完成，等待操作..."
        });
    }

    // 启动脚本
    initHook();
})();