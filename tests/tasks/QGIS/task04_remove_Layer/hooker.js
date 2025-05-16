// QGIS Layer Removal Hook Script
// Used to monitor QGIS layer removal operations and detect related parameters

(function() {
    // Script constants
    const SYMBOL_NAME = "_ZN16QgsMapLayerStore15removeMapLayersERK5QListIP11QgsMapLayerE"; // QgsMapLayerStore::removeMapLayers function symbol
    
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
            message: "QGIS layer removal monitoring script started"
        });
        
        // Find addVectorLayer function
        let removeLayersAddr = Module.findExportByName(null, SYMBOL_NAME);
        
        // If not found, try scanning all loaded modules
        if (!removeLayersAddr) {
            sendEvent("function_search_start", {
                message: "Searching for QgsMapLayerStore::removeMapLayers function..."
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
                            removeLayersAddr = symbol;
                        }
                    }
                },
                onComplete: function() {}
            });
            
            // If still not found, report error
            if (!removeLayersAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "Cannot find QgsMapLayerStore::removeMapLayers function"
                });
                return;
            }
        }
        
        // Report function found
        sendEvent("removeLayer_function_found", {
            address: removeLayersAddr.toString(),
            message: "Found QgsMapLayerStore::removeMapLayers function"
        });
        
        // Install hook
        Interceptor.attach(removeLayersAddr, {
            onEnter: function(args) {
                try {
                    const layerPointer = args[1];
                    const nameQString = layerPointer.readPointer().add(0x10).readPointer().add(0x20); // Get QString pointer
                    const name = qstringToString(nameQString);
                    console.log("Removing layer, name:", name);
                    // Send event notification
                    sendEvent("layer_removed", {
                        name: name,
                        message: `Layer removal detected, name: ${name}`
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
            message: "Hook installation complete, waiting for layer removal operations..."
        });
    }
    
    // Execute hook initialization immediately
    initHook();
})();