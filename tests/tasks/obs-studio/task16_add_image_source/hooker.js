// 用于监控OBS Studio中添加图像源和设置不透明度的操作

(function () {
    // 脚本设置
    const EVENT_ON_ENTER = "function called";
    const EVENT_ON_LEAVE = "function returned";
    
    const MESSAGE_source_created = "图像源创建成功";
    const MESSAGE_opacity_set = "不透明度设置成功";
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
    function getFunctionAddress(functionName) {
        console.log("[Debug] 正在查找函数:", functionName);
        const funcAddr = DebugSymbol.getFunctionByName(functionName);
        if (!funcAddr) {
            console.log("[Error] 未找到函数:", functionName);
            sendEvent("error", {
                error_type: "function_not_found",
                message: `无法找到函数 ${functionName}`
            });
            return null;
        }

        console.log("[Debug] 找到函数地址:", functionName, funcAddr);
        sendEvent("function_found", {
            address: funcAddr.toString(),
            message: `找到函数 ${functionName} 的实际地址`
        });
        return funcAddr;
    }

    // 存储已创建的图像源
    const imageSources = new Map();

    // 监控图像源的创建
    function hookSourceCreate() {
        console.log("[Hook] 开始设置obs_source_create钩子");
        const funcAddr = getFunctionAddress("obs_source_create");
        if (!funcAddr) return;

        Interceptor.attach(funcAddr, {
            onEnter(args) {
                this.source_id = args[0].readCString(-1);
                console.log("[obs_source_create] onEnter - source_id:", this.source_id);
                
                if (this.source_id === "image_source") {
                    console.log("[obs_source_create] 检测到图像源创建");
                    sendEvent(EVENT_ON_ENTER, {
                        function: "obs_source_create",
                        message: "正在创建图像源"
                    });
                }
            },
            onLeave(retval) {
                if (this.source_id === "image_source" && retval != 0) {
                    console.log("[obs_source_create] 图像源创建完成，源指针:", retval);
                    // 保存源指针以便后续使用
                    imageSources.set(retval.toString(), {
                        ptr: retval,
                        properties: {}
                    });
                    console.log("[Debug] 当前跟踪的图像源数量:", imageSources.size);
                }
            }
        });
    }

    // 监控源属性更新
    function hookSourceUpdate() {
        console.log("[Hook] 开始设置obs_source_update钩子");
        const funcAddr = getFunctionAddress("obs_source_update");
        if (!funcAddr) return;

        Interceptor.attach(funcAddr, {
            onEnter(args) {
                this.source = args[0];
                this.settings = args[1];

                if (this.source && imageSources.has(this.source.toString())) {
                    console.log("[obs_source_update] 检测到已跟踪的图像源更新");
                    try {
                        const settings = new OBSData(this.settings);
                        const source = new OBSSource(this.source);
                        const source_name = source.getName();
                        const image_path = settings.getString("file");
                        
                        console.log("[obs_source_update] 属性值 - source_name:", source_name);
                        console.log("[obs_source_update] 属性值 - image_path:", image_path);
                        
                        if (source_name && image_path) {
                            const sourceInfo = imageSources.get(this.source.toString());
                            sourceInfo.properties = {
                                source_name: source_name,
                                image_path: image_path
                            };
                            
                            sendEvent("image_source_added", {
                                source_name: source_name,
                                image_path: image_path,
                                message: MESSAGE_source_created
                            });
                        }
                    } catch (error) {
                        console.log("[Error] obs_source_update处理失败:", error);
                    }
                }
            }
        });
    }

    // 监控滤镜的添加
    function hookFilterAdd() {
        console.log("[Hook] 开始设置obs_source_filter_add钩子");
        const funcAddr = getFunctionAddress("obs_source_filter_add");
        if (!funcAddr) return;

        Interceptor.attach(funcAddr, {
            onEnter(args) {
                this.source = args[0];
                this.filter = args[1];
                
                if (this.source && imageSources.has(this.source.toString())) {
                    try {
                        const source = new OBSSource(this.source);
                        const filter = new OBSSource(this.filter);
                        const source_name = source.getName();
                        const filter_id = filter.getId();
                        
                        console.log("[obs_source_filter_add] source:", source_name);
                        console.log("[obs_source_filter_add] filter_id:", filter_id);
                        
                        // 保存滤镜信息以便后续处理
                        if (filter_id === "color_key_filter_v2" || filter_id === "chroma_key_filter_v2") {
                            const sourceInfo = imageSources.get(this.source.toString());
                            sourceInfo.filter = this.filter;
                            sourceInfo.ptr = this.source;
                        }
                    } catch (error) {
                        console.log("[Error] 获取滤镜信息失败:", error);
                    }
                }
            }
        });
    }

    // 监控滤镜属性更新
    function hookFilterUpdate() {
        console.log("[Hook] 开始设置obs_source_update钩子（用于滤镜）");
        const funcAddr = getFunctionAddress("obs_source_update");
        if (!funcAddr) return;

        Interceptor.attach(funcAddr, {
            onEnter(args) {
                this.source = args[0];
                this.settings = args[1];

                // 检查所有图像源的滤镜
                for (const [_, sourceInfo] of imageSources) {
                    if (sourceInfo.filter && this.source.equals(sourceInfo.filter)) {
                        try {
                            const settings = new OBSData(this.settings);
                            const opacity = settings.getDouble("opacity", 1.0);
                            // 使用图像源的指针而不是滤镜的指针
                            const source = new OBSSource(sourceInfo.ptr);
                            const source_name = source.getName();

                            console.log("[Filter Update] 源:", source_name);
                            console.log("[Filter Update] 不透明度:", opacity);

                            sendEvent("opacity_set", {
                                source_name: source_name,
                                opacity: opacity * 100,  // 转换为百分比
                                message: MESSAGE_opacity_set
                            });
                        } catch (error) {
                            console.log("[Error] 处理滤镜更新失败:", error);
                        }
                        break;
                    }
                }
            }
        });
    }

    // OBSData类用于解析OBS的数据结构
    class OBSData {
        constructor(ptr) {
            console.log("[OBSData] 创建新实例，指针:", ptr);
            this.ptr = ptr;
        }
        
        getString(key) {
            console.log("[OBSData] 获取字符串值，键:", key);
            const func = new NativeFunction(
                getFunctionAddress("obs_data_get_string"),
                'pointer',
                ['pointer', 'pointer']
            );
            const keyPtr = Memory.allocUtf8String(key);
            const strPtr = func(this.ptr, keyPtr);
            const value = strPtr.readCString(-1);
            console.log("[OBSData] 获取到的值:", value);
            return value;
        }

        getDouble(key, defaultValue = 1.0) {
            console.log("[OBSData] 获取浮点数值，键:", key);
            const func = new NativeFunction(
                getFunctionAddress("obs_data_get_double"),
                'double',
                ['pointer', 'pointer', 'double']
            );
            const keyPtr = Memory.allocUtf8String(key);
            const value = func(this.ptr, keyPtr, defaultValue);
            console.log("[OBSData] 获取到的值:", value);
            return value;
        }
    }

    // OBSSource类用于操作OBS的源
    class OBSSource {
        constructor(ptr) {
            console.log("[OBSSource] 创建新实例，指针:", ptr);
            this.ptr = ptr;
        }
        
        getName() {
            console.log("[OBSSource] 获取源名称");
            const func = new NativeFunction(
                getFunctionAddress("obs_source_get_name"),
                'pointer',
                ['pointer']
            );
            const namePtr = func(this.ptr);
            const name = namePtr.readCString(-1);
            console.log("[OBSSource] 获取到的源名称:", name);
            return name;
        }

        getId() {
            console.log("[OBSSource] 获取源ID");
            const func = new NativeFunction(
                getFunctionAddress("obs_source_get_id"),
                'pointer',
                ['pointer']
            );
            const idPtr = func(this.ptr);
            const id = idPtr.readCString(-1);
            console.log("[OBSSource] 获取到的源ID:", id);
            return id;
        }
    }

    // 初始化钩子
    function initHook() {
        console.log("[Init] 开始初始化钩子");
        sendEvent("script_initialized", {
            message: MESSAGE_script_initialized
        });

        // 初始化各个钩子
        hookSourceCreate();
        hookSourceUpdate();
        hookFilterAdd();
        hookFilterUpdate();

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