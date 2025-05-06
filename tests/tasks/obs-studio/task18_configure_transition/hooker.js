(function () {
    // 脚本设置
    const MESSAGE_script_initialized = "监控脚本已启动";
    const MESSAGE_hook_installed = "监控钩子安装完成，等待操作...";

    // 向评估系统发送事件
    function sendEvent(eventType, data = {}) {
        console.log("[Event]", eventType, JSON.stringify(data, null, 2));
        const payload = {
            event: eventType,
            ...data,
            timestamp: new Date().getTime()
        };
        send(payload);
    }

    // 获取函数地址
    function getFunctionAddress(functionName, symbolName) {
        console.log(`[Debug] 尝试获取函数 ${functionName} (符号: ${symbolName}) 的地址`);

        const funcAddr = DebugSymbol.getFunctionByName(symbolName);
        if (!funcAddr) {
            console.log(`[Error] 无法找到函数 ${functionName} (符号: ${symbolName})`);
            return null;
        }

        console.log(`[Debug] 找到函数 ${functionName} (符号: ${symbolName}) 的实际地址: ${funcAddr.toString()}`);
        return funcAddr;
    }

    // 初始化转场配置钩子
    function hookTransitionConfig() {
        // 监控转场开始函数
        let startFunc = "obs_transition_start";
        let startSymbol = "obs_transition_start";

        const startAddr = getFunctionAddress(startFunc, startSymbol);
        if (startAddr) {
            Interceptor.attach(startAddr, {
                onEnter(args) {
                    this.transition = args[0];
                    this.duration = args[2].toInt32();
                    this.dest = args[3];
                    console.log(`[Debug] 转场开始函数被调用，持续时间：${this.duration}ms`);
                },
                
                onLeave(retval) {
                    // 获取转场名称
                    const getSourceName = new NativeFunction(
                        DebugSymbol.getFunctionByName("obs_source_get_name"),
                        'pointer',
                        ['pointer']
                    );
                    const namePtr = getSourceName(this.transition);
                    const transitionName = namePtr.readCString();
                    const destName = getSourceName(this.dest).readCString();

                    console.log(`[Debug] 转场开始：类型=${transitionName}，持续时间=${this.duration}ms`);
                    
                    // 发送转场配置信息
                    sendEvent("transition_executed", {
                        transition_name: transitionName,
                        duration_ms: this.duration,
                        success: retval.toInt32() !== 0,
                        dest: destName
                    });
                }
            });
        }
    }

    // 初始化钩子
    function initHook() {
        console.log("[Init] 开始初始化钩子");
        sendEvent("script_initialized", {
            message: MESSAGE_script_initialized
        });

        // 初始化转场配置钩子
        hookTransitionConfig();
        
        console.log("[Init] 钩子初始化完成");
        sendEvent("hook_installed", {
            message: MESSAGE_hook_installed
        });
    }

    // 启动脚本
    console.log("[Start] 脚本开始执行");
    initHook();
    console.log("[Start] 脚本执行完成，等待事件...");
})(); 