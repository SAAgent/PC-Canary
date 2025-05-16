// QGIS Project Loading Hook Script
// Used to monitor QGIS project loading operations and detect related parameters

(function() {
    // Script constants
    const SYMBOL_NAME = "_ZN10QgsProject4readERK7QString6QFlagsIN4Qgis15ProjectReadFlagEE"; // QgsProject::read(QString, Qgis::ProjectReadFlags) symbol
    
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
            message: "QGIS project loading monitoring script started"
        });
        
        // Find project load function
        let loadProjectAddr = Module.findExportByName(null, SYMBOL_NAME);
        
        // If not found, try scanning all loaded modules
        if (!loadProjectAddr) {
            sendEvent("function_search_start", {
                message: "Searching for QgsProject::read function..."
            });
            
            // Enumerate modules
            Process.enumerateModules({
                onMatch: function(module) {
                    if (module.name.includes("qgis_core")) {
                        sendEvent("module_found", {
                            module_name: module.name,
                            base_address: module.base.toString()
                        });
                        
                        // Search for symbol in qgis module
                        const symbol = module.findExportByName(SYMBOL_NAME);
                        if (symbol) {
                            loadProjectAddr = symbol;
                        }
                    }
                },
                onComplete: function() {}
            });
            
            // If still not found, report error
            if (!loadProjectAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "Cannot find QgsProject::read function"
                });
                return;
            }
        }
        
        // Report function found
        sendEvent("load_function_found", {
            address: loadProjectAddr.toString(),
            message: "Found QgsProject::read function"
        });
        
        // Install hook
        Interceptor.attach(loadProjectAddr, {
            onEnter: function(args) {
                try {
                    // Get second parameter (const QString &filename), first is this pointer
                    const pathQString = args[1];
                    const filePath = qstringToString(pathQString);
                    
                    console.log("Project loading path:", filePath);
                    
                    // Send event notification
                    sendEvent("project_loaded", {
                        path: filePath,
                        message: `Project loading detected: Path=${filePath}`
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
            message: "Hook installation complete, waiting for project loading operations..."
        });
    }
    
    // Execute hook initialization immediately
    initHook();
})();