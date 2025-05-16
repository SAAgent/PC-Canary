// QGIS CRS Configuration Hook Script
// Used to monitor QGIS CRS configuration operations and detect updates

(function() {
    // Script constants setup
    const SYMBOL_NAME = "_ZN10QgsProject6setCrsERK28QgsCoordinateReferenceSystemb"; // setCrs function symbol
    
    // Send event to evaluation system
    function sendEvent(eventType, data = {}) {
        const payload = {
            event: eventType,
            ...data,
            timestamp: new Date().getTime()
        };
        send(payload);
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
                message: "Searching for QgsProject::setCrs function..."
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
                    message: "Unable to find QgsProject::setCrs function"
                });
                return;
            }
        }
        
        // Report function found
        sendEvent("setCrs_function_found", {
            address: setCrsFuncAddr.toString(),
            message: "QgsProject::setCrs function found"
        });
        
        // Install hook
        Interceptor.attach(setCrsFuncAddr, {
            onEnter: function(args) {
                try {
                    const crsPtr = args[1];
                    // Get d pointer
                    const dPtr = crsPtr.readPointer();
                    
                    // Determine mSRID offset through reverse engineering
                    const mSRID = dPtr.add(56).readInt();
                    console.log("mSRID:", mSRID);
                    sendEvent("newCrs_detected", {
                        crs: mSRID,
                        message: `CRS change detected: crs=${mSRID}`
                    });
                } catch (error) {
                    sendEvent("error", {
                        error_type: "hook_execution_error",
                        message: `Error executing hook: ${error.message}`
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