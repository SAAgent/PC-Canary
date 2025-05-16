// QGIS New Project Creation Hook Script
// Used to monitor QGIS new project creation and saving operations and detect parameters

(function() {
    // Script constants
    const clearProject_SYMBOL_NAME="_ZN10QgsProject5clearEv" // QgsProject::clear function symbol
    const setPath_SYMBOL_NAME="_ZN10QgsProject11setFileNameERK7QString" // QgsProject::setFileName function symbol
    
    // Counter and timestamp for filtering automatic calls during startup
    let clearCounter = 0;
        
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

    // Initialize hooks and execute immediately
    function initHook() {
        sendEvent("script_initialized", {
            message: "QGIS new project creation monitoring script started"
        });
        
        // Find new project creation function QgsProject::clear
        let clearProjectAddr = Module.findExportByName(null, clearProject_SYMBOL_NAME);
        
        // If not found, try scanning all loaded modules
        if (!clearProjectAddr) {
            sendEvent("function_search_start", {
                message: "Searching for QgsProject::clear function..."
            });
            
            // Enumerate modules
            Process.enumerateModules({
                onMatch: function(module) {
                    if (module.name.includes("qgis_core")) {
                        sendEvent("module_found", {
                            module_name: module.name,
                            base_address: module.base.toString()
                        });
                        
                        // Search for symbol in qgis_core module
                        const symbol = module.findExportByName(clearProject_SYMBOL_NAME);
                        if (symbol) {
                            clearProjectAddr = symbol;
                        }
                    }
                },
                onComplete: function() {}
            });
            
            // If still not found, report error
            if (!clearProjectAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "Cannot find QgsProject::clear function"
                });
                return;
            }
        }
        
        // Report function found
        sendEvent("clear_function_found", {
            address: clearProjectAddr.toString(),
            message: "Found QgsProject::clear function"
        });
        
        // Find project save function QgsProject::setFileName
        let setFileNameAddr = Module.findExportByName(null, setPath_SYMBOL_NAME);
        
        // If not found, try scanning all loaded modules
        if (!setFileNameAddr) {
            sendEvent("function_search_start", {
                message: "Searching for QgsProject::setFileName function..."
            });
            
            // Enumerate modules
            Process.enumerateModules({
                onMatch: function(module) {
                    if (module.name.includes("qgis_core")) {
                        sendEvent("module_found", {
                            module_name: module.name,
                            base_address: module.base.toString()
                        });
                        
                        // Search for symbol in qgis_core module
                        const symbol = module.findExportByName(setPath_SYMBOL_NAME);
                        if (symbol) {
                            setFileNameAddr = symbol;
                        }
                    }
                },
                onComplete: function() {}
            });
            
            // If still not found, report error
            if (!setFileNameAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "Cannot find QgsProject::setFileName function"
                });
                return;
            }
        }
        
        // Report function found
        sendEvent("setPath_function_found", {
            address: setFileNameAddr.toString(),
            message: "Found QgsProject::setFileName function"
        });
        
        // Install hook - Create new project
        Interceptor.attach(clearProjectAddr, {
            onEnter: function(args) {
                try {
                    clearCounter++;
                    
                    
                    // Ignore automatic calls during startup (when counter is 1)
                    if (clearCounter > 1 ) {
                        console.log("Detected user creating new project");
                        
                        // Send event notification
                        sendEvent("newProject_created", {
                            message: "New project creation detected"
                        });
                    } else {
                        console.log("Ignoring project initialization during application startup");
                    }
                } catch (error) {
                    sendEvent("error", {
                        error_type: "hook_execution_error",
                        message: `Error monitoring new project creation: ${error.message}`,
                        stack: error.stack
                    });
                }
            }
        });
        
        // Install hook - Save project
        Interceptor.attach(setFileNameAddr, {
            onEnter: function(args) {
                try {
                    // Get second parameter of function (const QString &name), first is this pointer
                    const pathQString = args[1];
                    const filePath = qstringToString(pathQString);
                    
                    console.log("Project save path detected:", filePath);
                    
                    // Send event notification
                    sendEvent("newProject_saved", {
                        path: filePath,
                        message: `Project save settings detected: Path=${filePath}`
                    });
                } catch (error) {
                    sendEvent("error", {
                        error_type: "hook_execution_error",
                        message: `Error monitoring project saving: ${error.message}`,
                        stack: error.stack
                    });
                }
            }
        });
        
        sendEvent("hook_installed", {
            message: "Hook installation complete, waiting for new project creation and saving operations..."
        });
    }
    
    // Execute hook initialization immediately
    initHook();
})();