// QGIS Zoom to Layer Hook Script
// Used to monitor QGIS zoom to layer operations and detect related parameters

(function() {
    // Script constants
    const SYMBOL_NAME = "_ZN30QgsLayerTreeViewDefaultActions12zoomToLayersEP12QgsMapCanvasRK5QListIP11QgsMapLayerE"; // QgsLayerTreeViewDefaultActions::zoomToLayers function symbol
    
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
            message: "QGIS layer zoom monitoring script started"
        });
        
        // Find zoomToLayers function
        let zoomToLayersAddr = Module.findExportByName(null, SYMBOL_NAME);
        
        // If not found, try scanning all loaded modules
        if (!zoomToLayersAddr) {
            sendEvent("function_search_start", {
                message: "Searching for QgsLayerTreeViewDefaultActions::zoomToLayers function..."
            });
            
            // Enumerate modules
            Process.enumerateModules({
                onMatch: function(module) {
                    if (module.name.includes("qgis_gui")) {
                        sendEvent("module_found", {
                            module_name: module.name,
                            base_address: module.base.toString()
                        });
                        
                        // Search for symbol in qgis module
                        const symbol = module.findExportByName(SYMBOL_NAME);
                        if (symbol) {
                            zoomToLayersAddr = symbol;
                        }
                    }
                },
                onComplete: function() {}
            });
            
            // If still not found, report error
            if (!zoomToLayersAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "Cannot find QgsLayerTreeViewDefaultActions::zoomToLayers function"
                });
                return;
            }
        }
        
        // Report function found
        sendEvent("zoom_function_found", {
            address: zoomToLayersAddr.toString(),
            message: "Found QgsLayerTreeViewDefaultActions::zoomToLayers function"
        });
        
        // Install hook
        Interceptor.attach(zoomToLayersAddr, {
            onEnter: function(args) {
                try {
                    const layerPointer = args[2];
                    const nameQString = layerPointer.readPointer().add(0x10).readPointer().add(0x20); // Get QString pointer
                    const name = qstringToString(nameQString);
                    console.log("Zooming to layer, name:", name);
                    // Send event notification
                    sendEvent("layer_zoomed", {
                        name: name,
                        message: `Layer to zoom detected, name: ${name}`
                    });
                } catch (error) {
                    sendEvent("error", {
                        error_type: "hook_execution_error",
                        message: `Error during hook execution: ${error.message}`,
                        stack: error.stack
                    });
                }
            }
        });
        
        sendEvent("hook_installed", {
            message: "Hook installation complete, waiting for layer zoom operations..."
        });
    }
    
    // Execute hook initialization immediately
    initHook();
})();