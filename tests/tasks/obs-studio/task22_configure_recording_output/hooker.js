// OBS录制输出配置与测试监控钩子脚本
// 用于监听OBS的录制输出路径和格式配置，以及录制测试操作

(function () {
    // 脚本设置
    const FUNCTION_ConfigureRecording = "_ZN12SimpleOutput18ConfigureRecordingEb";
    const FUNCTION_StartRecording = "_ZN12SimpleOutput14StartRecordingEv";
    const FUNCTION_StopRecording = "_ZN12SimpleOutput13StopRecordingEb";
    const FUNCTION_OBSBasic_GetCurrentOutputPath = "_ZN8OBSBasic20GetCurrentOutputPathEv";
    const FUNCTION_OBSBasicSettings_SaveOutputSettings = "_ZN16OBSBasicSettings18SaveOutputSettingsEv";

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

        sendEvent("function_found", {
            address: funcAddr.toString(),
            message: `找到函数 ${functionName} 的实际地址`
        });
        return funcAddr;
    }

    // 初始化配置录制输出钩子
    function initConfigureRecordingHook() {
        const configureRecordingFuncAddr = getFunctionAddress(FUNCTION_ConfigureRecording);
        if (!configureRecordingFuncAddr) {
            return;
        }

        Interceptor.attach(configureRecordingFuncAddr, {
            onEnter: function(args) {
                this.updateReplayBuffer = args[1].toInt32();
                sendEvent("configure_recording_called", {
                    message: "拦截到配置录制输出函数调用",
                    updateReplayBuffer: this.updateReplayBuffer
                });
            },

            onLeave: function(retval) {
                sendEvent("configure_recording_returned", {
                    message: "配置录制输出函数返回",
                    result: retval.toInt32() !== 0
                });
            }
        });
    }

    // 初始化保存输出设置钩子
    function initSaveOutputSettingsHook() {
        const saveOutputSettingsFuncAddr = getFunctionAddress(FUNCTION_OBSBasicSettings_SaveOutputSettings);
        if (!saveOutputSettingsFuncAddr) {
            return;
        }

        Interceptor.attach(saveOutputSettingsFuncAddr, {
            onEnter: function(args) {
                // 保存this指针，用于在onLeave中访问
                this.settingsThis = args[0];
                sendEvent("save_output_settings_called", {
                    message: "拦截到保存输出设置函数调用"
                });
            },

            onLeave: function(retval) {
                sendEvent("save_output_settings_returned", {
                    message: "保存输出设置函数返回"
                });
                
                try {
                    // 根据用户提供的内存偏移信息获取配置文件路径
                    // this到this.main的偏移是40
                    const mainPtr = this.settingsThis.add(40).readPointer();
                    if (mainPtr.isNull()) {
                        sendEvent("error", {
                            error_type: "get_main_failed",
                            message: "获取main指针失败"
                        });
                        return;
                    }
                    
                    // this.main.basicConfig和this.main的偏移是800
                    const basicConfigPtr = mainPtr.add(800).readPointer();
                    if (basicConfigPtr.isNull()) {
                        sendEvent("error", {
                            error_type: "get_basic_config_failed",
                            message: "获取basicConfig指针失败"
                        });
                        return;
                    }
                    
                    // this.main.basicConfig.config.file指针和this.main.basicConfig指针的地址一样
                    // this.main.basicConfig.config.file指针指向一个字符串指针
                    const configFilePtr = basicConfigPtr.readPointer();
                    if (configFilePtr.isNull()) {
                        sendEvent("error", {
                            error_type: "get_config_file_failed",
                            message: "获取config.file指针失败"
                        });
                        return;
                    }
                    
                    const configFilePath = configFilePtr.readCString();
                    if (!configFilePath) {
                        sendEvent("error", {
                            error_type: "read_config_file_path_failed",
                            message: "读取配置文件路径失败"
                        });
                        return;
                    }
                    
                    // 发送配置文件路径到handler.py，让handler.py来读取和检查文件内容
                    // 这样可以确保在检查文件内容之前，文件已经被完全写入
                    sendEvent("config_file_found", {
                        message: "找到配置文件路径",
                        path: configFilePath
                    });
                    
                } catch (e) {
                    sendEvent("error", {
                        error_type: "check_config_failed",
                        message: `检查配置文件失败: ${e.message}`
                    });
                }
            }
        });
    }

    // 初始化开始录制钩子
    function initStartRecordingHook() {
        const startRecordingFuncAddr = getFunctionAddress(FUNCTION_StartRecording);
        if (!startRecordingFuncAddr) {
            return;
        }

        Interceptor.attach(startRecordingFuncAddr, {
            onEnter: function(args) {
                sendEvent("start_recording_called", {
                    message: "拦截到开始录制函数调用"
                });
            },

            onLeave: function(retval) {
                sendEvent("start_recording_returned", {
                    message: "开始录制函数返回",
                    result: retval.toInt32() !== 0
                });
            }
        });
    }

    // 初始化停止录制钩子
    function initStopRecordingHook() {
        const stopRecordingFuncAddr = getFunctionAddress(FUNCTION_StopRecording);
        if (!stopRecordingFuncAddr) {
            return;
        }

        Interceptor.attach(stopRecordingFuncAddr, {
            onEnter: function(args) {
                this.force = args[1].toInt32() !== 0;
                sendEvent("stop_recording_called", {
                    message: "拦截到停止录制函数调用",
                    force: this.force
                });
            },

            onLeave: function(retval) {
                sendEvent("stop_recording_returned", {
                    message: "停止录制函数返回"
                });
            }
        });
    }

    // 初始化钩子
    function initHook() {
        sendEvent("script_initialized", {
            message: "OBS录制输出配置与测试监控脚本已启动"
        });

        // 初始化各个钩子
        initConfigureRecordingHook();
        initSaveOutputSettingsHook();
        initStartRecordingHook();
        initStopRecordingHook();
        
        sendEvent("hook_installed", {
            message: "录制输出配置与测试监控钩子安装完成，等待操作..."
        });
    }

    // 启动脚本
    initHook();
})();
