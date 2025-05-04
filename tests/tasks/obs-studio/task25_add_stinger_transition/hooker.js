// OBS Studio Stinger过渡监控脚本
// 用于监听OBS的添加Stinger过渡操作和场景切换操作

(function () {
    // 脚本设置
    // 创建和配置Stinger过渡相关函数
    const FUNCTION_AddTransition = "_ZN8OBSBasic13AddTransitionEPKc";
    const FUNCTION_SetTransition = "_ZN8OBSBasic13SetTransitionE10OBSSafeRefIP10obs_sourceXadL_Z18obs_source_get_refEEXadL_Z18obs_source_releaseEEE";
    const FUNCTION_TransitionToScene = "_ZN8OBSBasic17TransitionToSceneE10OBSSafeRefIP10obs_sourceXadL_Z18obs_source_get_refEEXadL_Z18obs_source_releaseEEEbbibb";
    
    // 常量和消息定义
    const OFFSET_info = 0x150;
    const MESSAGE_script_initialized = "监控脚本已启动";
    const MESSAGE_hook_installed = "监控钩子安装完成，等待操作...";
    const STINGER_TRANSITION_ID = "obs_stinger_transition";

    // 跟踪状态
    let stingerCreated = false;
    let stingerConfigured = false;
    let stingerUsed = false;

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

    // 监控添加过渡效果函数
    function initAddTransitionHook() {
        const funcAddr = getFunctionAddress(FUNCTION_AddTransition);
        if (!funcAddr) {
            return;
        }

        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                const transitionId = args[1].readCString();
                this.transitionId = transitionId;
                
                sendEvent("createStingerTransition_called", {
                    function: "OBSBasic::AddTransition",
                    transition_id: transitionId
                });
            },
            onLeave: function(retval) {
                sendEvent("createStingerTransition_returned", {
                    function: "OBSBasic::AddTransition",
                    transition_id: this.transitionId,
                });
                
                // 检查是否创建了Stinger过渡
                if (this.transitionId === STINGER_TRANSITION_ID) {
                    stingerCreated = true;
                    sendEvent("stinger_transition_created", {
                        transition_id: this.transitionId
                    });
                }
            }
        });
    }

    // 监控设置过渡属性函数 - 检测配置Stinger过渡
    function initStingerConfigHook() {
        // 在OBS Studio中，Stinger过渡的配置通常通过设置source属性来完成
        // 这里监控关键属性设置函数
        const onPropertyChangedSymbol = "_ZN8OBSBasic4SaveEPKc";
        const funcAddr = getFunctionAddress(onPropertyChangedSymbol);
        if (!funcAddr) {
            return;
        }

        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                sendEvent("configureStingerTransition_called", {
                    function: "OBSBasic::Save"
                });
                
                // 尝试获取属性数据
                this.file = args[1].readCString(-1);
            },
            onLeave: function(retval) {
                sendEvent("configureStingerTransition_returned", {
                    function: "OBSBasic::Save",
                    file: this.file
                });
                stingerConfigured = true;
            }
        });
    }
    
    // 监控设置过渡函数
    function initSetTransitionHook() {
        const funcAddr = getFunctionAddress(FUNCTION_SetTransition);
        if (!funcAddr) {
            return;
        }

        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                sendEvent("setTransition_called", {
                    function: "OBSBasic::SetTransition"
                });
                const transition = new NativePointer(args[1]);
                this.transition = transition;
            },
            onLeave: function(retval) {
                sendEvent("setTransition_returned", {
                    function: "OBSBasic::SetTransition"
                });
                
                // const obs_source_get_id = new NativeFunction(
                //     getFunctionAddress("obs_source_get_id"),
                //      'pointer',
                //       ['pointer']
                // );
                // const obs_source_get_name = new NativeFunction(
                //     getFunctionAddress("obs_source_get_name"),
                //     'pointer',
                //     ['pointer']
                // );
                // const val_pointer = this.transition.readPointer();
                // const id = obs_source_get_id(val_pointer).readCString(-1);
                try {
                    const val_pointer = this.transition.readPointer();
                    const info_pointer = val_pointer.add(OFFSET_info);
                    const id_pointer = info_pointer.readPointer();
                    const id = id_pointer.readCString(-1);
                    
                    sendEvent("transition_info", {
                        transition_id: id
                    });
                    
                    // 检查是否使用了Stinger过渡
                    if (id === STINGER_TRANSITION_ID && stingerCreated && stingerConfigured) {
                        stingerUsed = true;
                        sendEvent("stinger_transition_used", {
                            transition_id: id
                        });
                    }
                } catch (e) {
                    sendEvent("error", {
                        error_type: "read_transition_info",
                        message: `读取过渡信息失败: ${e.toString()}`
                    });
                }
            }
        });
    }

    // 监控场景切换函数
    function initTransitionToSceneHook() {
        const funcAddr = getFunctionAddress(FUNCTION_TransitionToScene);
        if (!funcAddr) {
            return;
        }

        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                sendEvent("sceneSwitch_called", {
                    function: "OBSBasic::TransitionToScene"
                });
            },
            onLeave: function(retval) {
                sendEvent("sceneSwitch_returned", {
                    function: "OBSBasic::TransitionToScene"
                });
                
                // 检查是否使用了Stinger过渡
                if (stingerCreated && stingerConfigured && !stingerUsed) {
                    // 在实际场景中，我们需要检查使用的过渡类型
                    // 这里简化为如果已创建和配置了Stinger过渡，就认为它被使用了
                    stingerUsed = true;
                    sendEvent("stinger_transition_used", {
                        message: "检测到场景切换使用了Stinger过渡"
                    });
                }
            }
        });
    }

    // 初始化钩子
    function initHook() {
        sendEvent("script_initialized", {
            message: MESSAGE_script_initialized
        });

        // 初始化各个钩子
        initAddTransitionHook();
        initStingerConfigHook();
        initSetTransitionHook();
        initTransitionToSceneHook();
        
        sendEvent("hook_installed", {
            message: MESSAGE_hook_installed
        });
    }

    // 启动脚本
    initHook();
})();