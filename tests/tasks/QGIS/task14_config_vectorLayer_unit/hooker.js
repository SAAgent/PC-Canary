// QGIS Vector Layer Unit Configuration Hook Script
// Used to monitor QGIS vector layer unit setting operations and detect related parameters

(function () {
    // Script constants setup
    const SYMBOL_NAME = "_ZNK9QgsSymbol13setOutputUnitEN4Qgis10RenderUnitE"; // QgsSymbol::setOutputUnit function symbol

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
    
    // Unit enum value mapping to names
    const unitNames = {
        0: "Millimeters",
        1: "MapUnits",
        2: "Pixels",
        3: "Percentage",
        4: "Points",
        5: "Inches"
    };

    // Initialize hook and execute immediately
    function initHook() {
        sendEvent("script_initialized", {
            message: "QGIS vector layer unit configuration monitoring script has started"
        });

        // Find setOutputUnit function
        let setUnitAddr = Module.findExportByName(null, SYMBOL_NAME);

        // If not found, try scanning all loaded modules
        if (!setUnitAddr) {
            sendEvent("function_search_start", {
                message: "Searching for QgsSymbol::setOutputUnit function..."
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
                            setUnitAddr = symbol;
                        }
                    }
                },
                onComplete: function () { }
            });

            // If still not found, report error
            if (!setUnitAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "Unable to find QgsSymbol::setOutputUnit function"
                });
                return;
            }
        }

        // Report function found
        sendEvent("set_function_found", {
            address: setUnitAddr.toString(),
            message: "Found QgsSymbol::setOutputUnit function"
        });
        
        // Install hook
        Interceptor.attach(setUnitAddr, {
            onEnter: function(args) {
                try {
                    // Get this pointer and enum parameter
                    const thisPtr = args[0];
                    const unitValue = parseInt(args[1].toString());
                    
                    // Get layer name
                    const layerPtr = thisPtr.add(0x58).readPointer();
                    if (!layerPtr.isNull()) {
                        const nameQString = layerPtr.add(0x20);
                        const layerName = qstringToString(nameQString);

                        console.log("Setting layer unit, layer name:", layerName);

                        // Send layer name event
                        sendEvent("layer_set", {
                            name: layerName,
                            message: `Detected layer for unit setting, name: ${layerName}`
                        });

                        // Convert enum value to unit name
                        const unitName = unitNames[unitValue] || `Unknown unit(${unitValue})`;
                        console.log("Setting unit to:", unitName, "Original enum value:", unitValue);

                        // Send unit event
                        sendEvent("unit_set", {
                            layer: layerName,
                            unit: unitName,
                            unit_value: unitValue,
                            message: `Detected unit setting for layer ${layerName}: ${unitName}`
                        });
                    }
                } catch (error) {
                    sendEvent("error", {
                        error_type: "hook_execution_error",
                        message: `Error executing hook: ${error.message}`,
                        stack: error.stack
                    });
                }
            }
        });

        sendEvent("hook_installed", {
            message: "Hook installation completed, waiting for layer unit setting operations..."
        });
    }

    // Execute hook initialization immediately
    initHook();
})();