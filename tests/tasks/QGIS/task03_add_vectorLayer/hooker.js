// QGIS Vector Layer Addition Hook Script
// Used to monitor QGIS vector layer addition operations and detect related parameters

(function() {
    // Script constants
    const SYMBOL_NAME = "_ZN10QgsProject11addMapLayerEP11QgsMapLayerbb"; // QgsProject::addMapLayer function symbol
    
    // Send events to evaluation system
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
        const d    = qstr.readPointer();                         // QString::d
        const len  = d.add(SIZE_OFFSET).readU32();               // QStringData::size
        const data = d.add(HEADER_SIZE);                         // first UTF‑16 char
        return Memory.readUtf16String(data, len);
    }

    // Initialize hooks and execute immediately
    function initHook() {
        sendEvent("script_initialized", {
            message: "QGIS vector layer addition monitoring script started"
        });
        
        // Find addVectorLayer function
        let addVectorLayerAddr = Module.findExportByName(null, SYMBOL_NAME);
        
        // If not found, try scanning all loaded modules
        if (!addVectorLayerAddr) {
            sendEvent("function_search_start", {
                message: "Searching for QgsProject::addMapLayer function..."
            });
            
            // Enumerate modules
            Process.enumerateModules({
                onMatch: function(module) {
                    if (module.name.includes("qgis_app") ) {
                        sendEvent("module_found", {
                            module_name: module.name,
                            base_address: module.base.toString()
                        });
                        
                        // Search for symbol in qgis_app module
                        const symbol = module.findExportByName(SYMBOL_NAME);
                        if (symbol) {
                            addVectorLayerAddr = symbol;
                        }
                    }
                },
                onComplete: function() {}
            });
            
            // If still not found, report error
            if (!addVectorLayerAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "Cannot find QgsProject::addMapLayer function"
                });
                return;
            }
        }
        
        // Report function found
        sendEvent("addvectorLayer_function_found", {
            address: addVectorLayerAddr.toString(),
            message: "Found QgsProject::addMapLayer function"
        });
        
        // Install hook
        Interceptor.attach(addVectorLayerAddr, {
            onEnter: function(args) {
                try {
                    const layerPointer = args[1];
                    const uriQString = layerPointer.add(0x18); 
                    const uri = qstringToString(uriQString);
                    console.log("Adding vector layer, path:", uri);
                    // Send event notification
                    sendEvent("vector_layer_added", {
                        uri: uri,
                        message: `Vector layer addition detected, path: ${uri}`
                    });
                } catch (error) {
                    sendEvent("error", {
                        error_type: "hook_execution_error",
                        message: `Error during hook execution: ${error.message}`,
                    });
                }
            }
            
        });
        
        sendEvent("hook_installed", {
            message: "Hook installation complete, waiting for vector layer addition operations..."
        });
    }
    
    // Execute hook initialization immediately
    initHook();
})();