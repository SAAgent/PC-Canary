(function () {
    // 脚本设置
    const MESSAGE_script_initialized = "监控脚本已启动";
    const MESSAGE_hook_installed = "监控钩子安装完成，等待操作...";
    const MESSAGE_config_updated = "检测到配置更新";

    // 向评估系统发送事件
    function sendEvent(eventType, data = {}) {
        const payload = {
            event: eventType,
            ...data,
            timestamp: new Date().getTime()
        };
        send(payload);
    }

    // 获取函数地址
    function getFunctionAddress(functionName) {
        const funcAddr = DebugSymbol.getFunctionByName(functionName);
        if (!funcAddr) {
            sendEvent("error", {
                error_type: "function_not_found",
                message: `无法找到函数 ${functionName}`
            });
            return null;
        }

        sendEvent("debug", {
            address: funcAddr.toString(),
            message: `找到函数 ${functionName} 的实际地址`
        });
        return funcAddr;
    }

    // 监控配置文件修改
    function hookConfigSave() {
        let function_name = "config_save_safe";
        let symbol_name = "config_save_safe";

        Interceptor.attach(getFunctionAddress(symbol_name), {
            onEnter(args) {
                this.configFile = args[0];
                sendEvent("debug", {
                    message: "正在保存配置文件",
                    function: function_name
                });
            },
            onLeave(retval) {
                sendEvent("config_saved", {
                    message: MESSAGE_config_updated,
                    function: function_name,
                    result: retval.toInt32(),
                    configFile: this.configFile.readPointer().readCString()
                });
            }
        });
    }

    // 监控视频比特率设置
    function hookVideoBitrateSet() {
        let function_name = "config_set_int";
        let symbol_name = "config_set_int";

        Interceptor.attach(getFunctionAddress(symbol_name), {
            onEnter(args) {
                if (args[0] === null) return;

                this.section = args[1].readCString();
                this.name = args[2].readCString();
                this.value = args[3].toInt32();

                // 检查是否是设置视频比特率
                if (this.section === "SimpleOutput" && this.name === "VBitrate" && this.value === 2000) {
                    sendEvent("video_bitrate_set", {
                        message: "视频比特率已设置为2000",
                        section: this.section,
                        name: this.name,
                        value: this.value
                    });
                }

                // 检查是否是设置回放时间
                if (this.section === "SimpleOutput" && this.name === "RecRBTime" && this.value === 30) {
                    sendEvent("replay_time_set", {
                        message: "最大回放时间已设为30秒",
                        section: this.section,
                        name: this.name,
                        value: this.value
                    });
                }
            },
            onLeave(retval) {}
        });
    }

    // 监控编码预设设置
    function hookEncoderPresetSet() {
        let function_name = "config_set_string";
        let symbol_name = "config_set_string";

        Interceptor.attach(getFunctionAddress(symbol_name), {
            onEnter(args) {
                if (args[0] === null) return;

                this.section = args[1].readCString();
                this.name = args[2].readCString();
                
                // 检查字符串值是否为空
                if (args[3] !== null) {
                    this.value = args[3].readCString();
                    console.log("设置值:", this.value);
                
                    // 检查是否是设置编码预设
                    if (this.section === "SimpleOutput" && this.name === "Preset" && this.value === "faster") {
                        sendEvent("encoder_preset_set", {
                            message: "编码预设已设置为faster",
                            section: this.section,
                            name: this.name,
                            value: this.value
                        });
                    }

                    // 检查是否是设置音频比特率
                    if (this.section === "SimpleOutput" && this.name === "ABitrate" && this.value === "320") {
                        sendEvent("audio_bitrate_set", {
                            message: "音频比特率已设置为320",
                            section: this.section,
                            name: this.name,
                            value: this.value
                        });
                    }
                }
            },
            onLeave(retval) {}
        });
    }

    // 监控回放缓冲区启用设置
    function hookReplayBufferEnable() {
        let function_name = "config_set_bool";
        let symbol_name = "config_set_bool";

        Interceptor.attach(getFunctionAddress(symbol_name), {
            onEnter(args) {
                if (args[0] === null) return;

                this.section = args[1].readCString();
                this.name = args[2].readCString();
                this.value = args[3].toInt32();

                // 检查是否是启用回放缓冲区
                if (this.section === "SimpleOutput" && this.name === "RecRB" && this.value === 1) {
                    sendEvent("replay_buffer_enabled", {
                        message: "回放缓冲区已启用",
                        section: this.section,
                        name: this.name,
                        value: this.value
                    });
                }
            },
            onLeave(retval) {}
        });
    }

    // 初始化全部钩子函数
    function initHook() {
        sendEvent("script_initialized", {
            message: MESSAGE_script_initialized
        });

        // 初始化各个钩子
        hookConfigSave();
        hookVideoBitrateSet();
        hookEncoderPresetSet();
        hookReplayBufferEnable();

        sendEvent("hook_installed", {
            message: MESSAGE_hook_installed
        });
    }

    // 启动脚本
    initHook();
})();