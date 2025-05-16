// QGIS CRS Configuration Hook Script
// Used to monitor QGIS CRS configuration operations and detect updates

(function() {
    // Script constants setup
    const SYMBOL_NAME = "_ZN11QgsMapLayer6setCrsERK28QgsCoordinateReferenceSystemb"; // setCrs function symbol
    
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
            message: "QGIS CRS monitoring script has started"
        });
        
        // Find setCrs function
        let setCrsFuncAddr = Module.findExportByName(null, SYMBOL_NAME);
        
        // If not found, try scanning all loaded modules
        if (!setCrsFuncAddr) {
            sendEvent("function_search_start", {
                message: "Searching for QgsMapLayer::setCrs function..."
            });
            
            // Enumerate modules
            Process.enumerateModules({
                onMatch: function(module) {
                    if (module.name.includes("qgis_core")) {
                        sendEvent("module_found", {
                            module_name: module.name,
                            base_address: module.base.toString()
                        });
                        
                        // Find symbol in qgis_core module
                        const symbol = module.findExportByName(SYMBOL_NAME);
                        if (symbol) {
                            setCrsFuncAddr = symbol;
                        }
                    }
                },
                onComplete: function() {}
            });
            
            // If still not found, report error
            if (!setCrsFuncAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "Unable to find QgsMapLayer::setCrs function"
                });
                return;
            }
        }
        
        // Report function found
        sendEvent("modifyCrs_function_found", {
            address: setCrsFuncAddr.toString(),
            message: "Found QgsMapLayer::setCrs function"
        });
        
        // Install hook
        Interceptor.attach(setCrsFuncAddr, {
            onEnter: function(args) {
                try {
                    // Get layer name (this pointer)
                    const thisPtr = args[0];
                    // Layer name is at this+0x20 position
                    const nameQString = thisPtr.add(0x20);
                    const layerName = qstringToString(nameQString);
                    console.log("Layer name:", layerName);
                    
                    // First send layer name event
                    sendEvent("layerName_found", {
                        name: layerName,
                        message: `Detected operation on layer: ${layerName}`
                    });
                    
                    // Get CRS parameter
                    const crsPtr = args[1];
                    // Get d pointer
                    const dPtr = crsPtr.readPointer();
                    
                    // Determine mSRID offset through reverse engineering
                    const mSRID = dPtr.add(56).readInt();
                    console.log("mSRID:", mSRID);
                    
                    // Send CRS change event
                    sendEvent("newCrs_detected", {
                        layer: layerName,
                        crs: mSRID,
                        message: `Detected CRS change for layer ${layerName} to: ${mSRID}`
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
            message: "Hook installation completed, waiting for CRS change operations..."
        });
    }
    
    // Execute hook initialization immediately
    initHook();
})();