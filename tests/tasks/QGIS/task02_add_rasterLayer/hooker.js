// QGIS Layer Addition Hook Script
// Used to monitor QGIS raster layer addition operations and detect related parameters

(function() {
    // Script constants setup
    const SYMBOL_NAME = "_ZN10QgsProject11addMapLayerEP11QgsMapLayerbb"; // QgsProject::addMapLayer function symbol
    
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
        const d    = qstr.readPointer();                         // QString::d
        const len  = d.add(SIZE_OFFSET).readU32();               // QStringData::size
        const data = d.add(HEADER_SIZE);                         // first UTF‑16 char
        return Memory.readUtf16String(data, len);
    }

    // Initialize hook and execute immediately
    function initHook() {
        sendEvent("script_initialized", {
            message: "QGIS raster layer monitoring script has started"
        });
        
        // Find addRasterLayer function
        let addRasterLayerAddr = Module.findExportByName(null, SYMBOL_NAME);
        
        // If not found, try scanning all loaded modules
        if (!addRasterLayerAddr) {
            sendEvent("function_search_start", {
                message: "Searching for QgsProject::addMapLayer function..."
            });
            
            // Enumerate modules
            Process.enumerateModules({
                onMatch: function(module) {
                    if (module.name.includes("qgis_core") ) {
                        sendEvent("module_found", {
                            module_name: module.name,
                            base_address: module.base.toString()
                        });
                        
                        // Find symbol in qgis_app module
                        const symbol = module.findExportByName(SYMBOL_NAME);
                        if (symbol) {
                            addRasterLayerAddr = symbol;
                        }
                    }
                },
                onComplete: function() {}
            });
            
            // If still not found, report error
            if (!addRasterLayerAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "Unable to find QgsAppLayerHandling::addRasterLayer function"
                });
                return;
            }
        }
        
        // Report function found
        sendEvent("addrasterLayer_function_found", {
            address: addRasterLayerAddr.toString(),
            message: "QgsProject::addMapLayer function found"
        });
        
        // Install hook
        Interceptor.attach(addRasterLayerAddr, {
            onEnter: function(args) {
                try {
                    const layerPointer = args[1];
                    const uriQString = layerPointer.add(0x18); 
                    const uri = qstringToString(uriQString);
                    console.log("Adding raster layer, path:", uri);
                    
                    // Send notification event
                    sendEvent("raster_layer_added", {
                        uri: uri,
                        message: `Detected raster layer addition, path: ${uri}`
                    });
                } catch (error) {
                    sendEvent("error", {
                        error_type: "hook_execution_error",
                        message: `Error executing hook: ${error.message}`,
                    });
                }
            }
            
        });
        
        sendEvent("hook_installed", {
            message: "Hook installation completed, waiting for raster layer addition operations..."
        });
    }
    
    // Execute hook initialization immediately
    initHook();
})();