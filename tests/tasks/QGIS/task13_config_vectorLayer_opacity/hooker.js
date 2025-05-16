// QGIS Vector Layer Opacity Configuration Hook Script
// Used to monitor QGIS vector layer opacity setting operations and detect related parameters

(function () {
    // Script constants setup
    const SYMBOL_NAME = "_ZN9QgsSymbol10setOpacityEd"; // QgsSymbol::setOpacity function symbol

    // Send event to evaluation system
    function sendEvent(eventType, data = {}) {
        const payload = {
            event: eventType,
            ...data,
            timestamp: new Date().getTime()
        };
        send(payload);
    }

    const HEADER_SIZE = 24;
    const SIZE_OFFSET = 4;

    function qstringToString(qstr) {
        try {
            const d = qstr.readPointer();                         // QString::d
            const len = d.add(SIZE_OFFSET).readU32();             // QStringData::size
            const data = d.add(HEADER_SIZE);                      // first UTF‑16 char
            return Memory.readUtf16String(data, len);
        } catch (error) {
            console.log("Failed to parse QString:", error);
            return "";
        }
    }

    // Initialize hook and execute immediately
    function initHook() {
        sendEvent("script_initialized", {
            message: "QGIS vector layer opacity configuration monitoring script has started"
        });

        // Find setOpacity function
        let setOpacityAddr = Module.findExportByName(null, SYMBOL_NAME);

        // If not found, try scanning all loaded modules
        if (!setOpacityAddr) {
            sendEvent("function_search_start", {
                message: "Searching for QgsSymbol::setOpacity function..."
            });

            // Enumerate modules
            Process.enumerateModules({
                onMatch: function (module) {
                    if (module.name.includes("qgis_core")) {
                        sendEvent("module_found", {
                            module_name: module.name,
                            base_address: module.base.toString()
                        });

                        // Find symbol in qgis_core module
                        const symbol = module.findExportByName(SYMBOL_NAME);
                        if (symbol) {
                            setOpacityAddr = symbol;
                        }
                    }
                },
                onComplete: function () { }
            });

            // If still not found, report error
            if (!setOpacityAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "Unable to find QgsSymbol::setOpacity function"
                });
                return;
            }
        }

        // Report function found
        sendEvent("set_function_found", {
            address: setOpacityAddr.toString(),
            message: "Found QgsSymbol::setOpacity function"
        });

        // Save original function
        const originalFunction = new NativeFunction(setOpacityAddr, 'void', ['pointer', 'double']);

        // Use replace instead of attach, and explicitly specify function signature
        Interceptor.replace(setOpacityAddr, new NativeCallback(function (thisPtr, opacity) {
            try {
                // Get layer name
                const layerPtr = thisPtr.add(0x58).readPointer();
                if (!layerPtr.isNull()) {
                    const nameQString = layerPtr.add(0x20);
                    const layerName = qstringToString(nameQString);

                    console.log("Setting layer opacity, layer name:", layerName);

                    // Send layer name event
                    sendEvent("layer_set", {
                        name: layerName,
                        message: `Detected layer for opacity setting, name: ${layerName}`
                    });

                    // Now opacity is correctly passed as float value
                    // Convert 0-1 range opacity to 0-100%
                    const opacityPercent = (opacity * 100).toFixed(1);
                    console.log("Setting opacity to:", opacityPercent, "%", "Original value:", opacity);

                    // Send opacity event
                    sendEvent("opacity_set", {
                        layer: layerName,
                        opacity: opacityPercent,
                        opacity_raw: opacity,
                        message: `Detected opacity setting for layer ${layerName}: ${opacityPercent}%`
                    });
                }
            } catch (error) {
                sendEvent("error", {
                    error_type: "hook_execution_error",
                    message: `Error executing hook: ${error.message}`,
                    stack: error.stack
                });
            }

            // Call original function to maintain functionality
            return originalFunction(thisPtr, opacity);
        }, 'void', ['pointer', 'double']));

        sendEvent("hook_installed", {
            message: "Hook installation completed, waiting for layer opacity setting operations..."
        });
    }

    // Execute hook initialization immediately
    initHook();
})();