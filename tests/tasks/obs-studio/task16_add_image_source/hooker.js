// Used to monitor the addition of image sources and setting opacity in OBS Studio

(function () {
    // Script settings
    const EVENT_ON_ENTER = "function called";
    const EVENT_ON_LEAVE = "function returned";

    const MESSAGE_source_created = "Image source created successfully";
    const MESSAGE_opacity_set = "Opacity set successfully";
    const MESSAGE_script_initialized = "Monitoring script has started";
    const MESSAGE_hook_installed = "Monitoring hook installed, waiting for operation...";

    // Send events to the evaluation system
    function sendEvent(eventType, data = {}) {
        console.log("[Event]", eventType, JSON.stringify(data, null, 2));
        const payload = {
            event: eventType,
            ...data,
            timestamp: new Date().getTime()
        };
        send(payload);
    }

    // Get function address
    function getFunctionAddress(functionName) {
        console.log("[Debug] Searching for function:", functionName);
        const funcAddr = DebugSymbol.getFunctionByName(functionName);
        if (!funcAddr) {
            console.log("[Error] Function not found:", functionName);
            sendEvent("error", {
                error_type: "function_not_found",
                message: `Cannot find function ${functionName}`
            });
            return null;
        }

        console.log("[Debug] Found function address:", functionName, funcAddr);
        sendEvent("function_found", {
            address: funcAddr.toString(),
            message: `Found the actual address of function ${functionName}`
        });
        return funcAddr;
    }

    // Store created image sources
    const imageSources = new Map();

    // Monitor image source creation
    function hookSourceCreate() {
        console.log("[Hook] Setting up obs_source_create hook");
        const funcAddr = getFunctionAddress("obs_source_create");
        if (!funcAddr) return;

        Interceptor.attach(funcAddr, {
            onEnter(args) {
                this.source_id = args[0].readCString(-1);
                console.log("[obs_source_create] onEnter - source_id:", this.source_id);

                if (this.source_id === "image_source") {
                    console.log("[obs_source_create] Detected image source creation");
                    sendEvent(EVENT_ON_ENTER, {
                        function: "obs_source_create",
                        message: "Creating image source"
                    });
                }
            },
            onLeave(retval) {
                if (this.source_id === "image_source" && retval != 0) {
                    console.log("[obs_source_create] Image source creation completed, source pointer:", retval);
                    // Save source pointer for later use
                    imageSources.set(retval.toString(), {
                        ptr: retval,
                        properties: {}
                    });
                    console.log("[Debug] Current tracked image sources count:", imageSources.size);
                }
            }
        });
    }

    // Monitor source property updates
    function hookSourceUpdate() {
        console.log("[Hook] Setting up obs_source_update hook");
        const funcAddr = getFunctionAddress("obs_source_update");
        if (!funcAddr) return;

        Interceptor.attach(funcAddr, {
            onEnter(args) {
                this.source = args[0];
                this.settings = args[1];

                if (this.source && imageSources.has(this.source.toString())) {
                    console.log("[obs_source_update] Detected tracked image source update");
                    try {
                        const settings = new OBSData(this.settings);
                        const source = new OBSSource(this.source);
                        const source_name = source.getName();
                        const image_path = settings.getString("file");

                        console.log("[obs_source_update] Property values - source_name:", source_name);
                        console.log("[obs_source_update] Property values - image_path:", image_path);

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
                        console.log("[Error] Failed to process obs_source_update:", error);
                    }
                }
            }
        });
    }

    // Monitor filter addition
    function hookFilterAdd() {
        console.log("[Hook] Setting up obs_source_filter_add hook");
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

                        const obs_source_get_settings = new NativeFunction(
                            getFunctionAddress("obs_source_get_settings"),
                            'pointer',
                            ['pointer']
                        );
                        const settingsPtr = obs_source_get_settings(this.filter);
                        const settings = new OBSData(settingsPtr);
                        const opacity = settings.getDouble("opacity", 1.0);
                        console.log("[obs_source_filter_add] Opacity:", opacity);

                        // Save filter information for later processing
                        if (filter_id === "color_key_filter_v2" || filter_id === "chroma_key_filter_v2") {
                            const sourceInfo = imageSources.get(this.source.toString());
                            sourceInfo.filter = this.filter;
                            sourceInfo.ptr = this.source;
                            sourceInfo.opacity = opacity;
                            sendEvent("filter_added", {
                                source_name: source_name,
                                filter_id: filter_id,
                                opacity: opacity * 100,  // Convert to percentage
                                message: "Filter added successfully"
                            });
                        }
                    } catch (error) {
                        console.log("[Error] Failed to retrieve filter information:", error);
                    }
                }
            }
        });
    }

    // Monitor filter property updates
    function hookFilterUpdate() {
        console.log("[Hook] Setting up obs_source_update hook (for filters)");
        const funcAddr = getFunctionAddress("obs_source_update");
        if (!funcAddr) return;

        Interceptor.attach(funcAddr, {
            onEnter(args) {
                this.source = args[0];
                this.settings = args[1];

                // Check all image sources' filters
                for (const [_, sourceInfo] of imageSources) {
                    if (sourceInfo.filter && this.source.equals(sourceInfo.filter)) {
                        try {
                            const settings = new OBSData(this.settings);
                            const opacity = settings.getDouble("opacity", 1.0);
                            // Use the image source's pointer instead of the filter's pointer
                            const source = new OBSSource(sourceInfo.ptr);
                            const source_name = source.getName();

                            console.log("[Filter Update] Source:", source_name);
                            console.log("[Filter Update] Opacity:", opacity);

                            sendEvent("opacity_set", {
                                source_name: source_name,
                                opacity: opacity * 100,  // Convert to percentage
                                message: MESSAGE_opacity_set
                            });
                        } catch (error) {
                            console.log("[Error] Failed to process filter update:", error);
                        }
                        break;
                    }
                }
            }
        });
    }

    // OBSData class for parsing OBS data structures
    class OBSData {
        constructor(ptr) {
            console.log("[OBSData] Creating new instance, pointer:", ptr);
            this.ptr = ptr;
        }

        getString(key) {
            console.log("[OBSData] Retrieving string value, key:", key);
            const func = new NativeFunction(
                getFunctionAddress("obs_data_get_string"),
                'pointer',
                ['pointer', 'pointer']
            );
            const keyPtr = Memory.allocUtf8String(key);
            const strPtr = func(this.ptr, keyPtr);
            const value = strPtr.readCString(-1);
            console.log("[OBSData] Retrieved value:", value);
            return value;
        }

        getDouble(key, defaultValue = 1.0) {
            console.log("[OBSData] Retrieving double value, key:", key);
            const func = new NativeFunction(
                getFunctionAddress("obs_data_get_double"),
                'double',
                ['pointer', 'pointer', 'double']
            );
            const keyPtr = Memory.allocUtf8String(key);
            const value = func(this.ptr, keyPtr, defaultValue);
            console.log("[OBSData] Retrieved value:", value);
            return value;
        }
    }

    // OBSSource class for manipulating OBS sources
    class OBSSource {
        constructor(ptr) {
            console.log("[OBSSource] Creating new instance, pointer:", ptr);
            this.ptr = ptr;
        }

        getName() {
            console.log("[OBSSource] Retrieving source name");
            const func = new NativeFunction(
                getFunctionAddress("obs_source_get_name"),
                'pointer',
                ['pointer']
            );
            const namePtr = func(this.ptr);
            const name = namePtr.readCString(-1);
            console.log("[OBSSource] Retrieved source name:", name);
            return name;
        }

        getId() {
            console.log("[OBSSource] Retrieving source ID");
            const func = new NativeFunction(
                getFunctionAddress("obs_source_get_id"),
                'pointer',
                ['pointer']
            );
            const idPtr = func(this.ptr);
            const id = idPtr.readCString(-1);
            console.log("[OBSSource] Retrieved source ID:", id);
            return id;
        }
    }

    // Initialize hooks
    function initHook() {
        console.log("[Init] Starting hook initialization");
        sendEvent("script_initialized", {
            message: MESSAGE_script_initialized
        });

        // Initialize individual hooks
        hookSourceCreate();
        hookSourceUpdate();
        hookFilterAdd();
        hookFilterUpdate();

        console.log("[Init] Hook initialization completed");
        sendEvent("hook_installed", {
            message: MESSAGE_hook_installed
        });
    }

    // Start script
    console.log("[Start] Script execution started");
    initHook();
    console.log("[Start] Script execution completed, waiting for events...");
})();