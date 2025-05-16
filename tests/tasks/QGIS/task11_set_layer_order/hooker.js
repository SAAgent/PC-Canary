// QGIS Layer Order Adjustment Hook Script
// Used to monitor QGIS layer order adjustment operations and detect related parameters

(function() {
    // Script constants setup
    const SYMBOL_NAME = "_ZN12QgsLayerTree19setCustomLayerOrderERK5QListIP11QgsMapLayerE"; // QgsLayerTree::setCustomLayerOrder function symbol
    
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
            message: "QGIS layer order monitoring script has started"
        });
        
        // Find setCustomLayerOrder function
        let setOrderAddr = Module.findExportByName(null, SYMBOL_NAME);
        
        // If not found, try scanning all loaded modules
        if (!setOrderAddr) {
            sendEvent("function_search_start", {
                message: "Searching for QgsLayerTree::setCustomLayerOrder function..."
            });
            
            // Enumerate modules
            Process.enumerateModules({
                onMatch: function(module) {
                    if (module.name.includes("qgis_core")) {
                        sendEvent("module_found", {
                            module_name: module.name,
                            base_address: module.base.toString()
                        });
                        
                        // Find symbol in qgis module
                        const symbol = module.findExportByName(SYMBOL_NAME);
                        if (symbol) {
                            setOrderAddr = symbol;
                        }
                    }
                },
                onComplete: function() {}
            });
            
            // If still not found, report error
            if (!setOrderAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "Unable to find QgsLayerTree::setCustomLayerOrder function"
                });
                return;
            }
        }
        
        // Report function found
        sendEvent("setOrder_function_found", {
            address: setOrderAddr.toString(),
            message: "Found QgsLayerTree::setCustomLayerOrder function"
        });
        
        // Install hook
        Interceptor.attach(setOrderAddr, {
            onEnter: function(args) {
                try {
                    // Get QList<QgsMapLayer *> parameter
                    const qlistPtr = args[1]; // Second parameter in args array (customLayerOrder)
                    
                    // Read QList begin and end, calculate element count
                    const begin = qlistPtr.readPointer().add(0x8).readU32();
                    const end = qlistPtr.readPointer().add(0xc).readU32();
                    const count = end - begin;
                    console.log(`Layer order list contains ${count} layers`);
                    
                    // Extract names of all layers
                    const layerNames = [];
                    
                    for (let i = 0; i < count; i++) {
                        // Calculate current element offset in QList
                        const elementOffset = 0x10 + (i * Process.pointerSize);
                        // Read current layer pointer
                        const layerPtr = qlistPtr.readPointer().add(elementOffset).readPointer();
                        // Read layer name (layer name QString is at offset 0x20)
                        const nameQString = layerPtr.add(0x20);
                        const name = qstringToString(nameQString);
                        
                        layerNames.push(name);
                        console.log(`Layer ${i+1}: ${name}`);
                    }
                    
                    // Send notification event
                    sendEvent("order_set", {
                        layer_count: count,
                        layer_names: layerNames,
                        order_string: layerNames.join(','),
                        message: `Detected layer order change: ${layerNames.join(',')}`
                    });
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
            message: "Hook installation completed, waiting for layer order adjustment operations..."
        });
    }
    
    // Execute hook initialization immediately
    initHook();
})();