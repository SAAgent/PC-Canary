// QGIS Map PDF Export Hook Script
// Used to monitor QGIS map PDF export operations and detect related parameters

(function() {
    // Script constants
    const setPath_SYMBOL_NAME="_ZN11QFileDialog15getSaveFileNameEP7QWidgetRK7QStringS4_S4_PS2_6QFlagsINS_6OptionEE" // QFileDialog::getSaveFileName function symbol
    const setSize_SYMBOL_NAME="_ZN14QgsMapSettings13setOutputSizeE5QSize" // QgsMapSettings::setOutputSize function symbol
        
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
            message: "QGIS map PDF export monitoring script started"
        });
        
        // Find path setting function
        let setPathAddr = Module.findExportByName(null, setPath_SYMBOL_NAME);
        
        // If not found, try scanning all loaded modules
        if (!setPathAddr) {
            sendEvent("function_search_start", {
                message: "Searching for QFileDialog::getSaveFileName function..."
            });
            
            // Enumerate modules
            Process.enumerateModules({
                onMatch: function(module) {
                    if (module.name.includes("Qt5") || module.name.includes("libQt5")) {
                        sendEvent("module_found", {
                            module_name: module.name,
                            base_address: module.base.toString()
                        });
                        
                        // Search for symbol in Qt5 module
                        const symbol = module.findExportByName(setPath_SYMBOL_NAME);
                        if (symbol) {
                            setPathAddr = symbol;
                        }
                    }
                },
                onComplete: function() {}
            });
            
            // If still not found, report error
            if (!setPathAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "Cannot find QFileDialog::getSaveFileName function"
                });
                return;
            }
        }
        
        // Report function found
        sendEvent("setPath_function_found", {
            address: setPathAddr.toString(),
            message: "Found QFileDialog::getSaveFileName function"
        });
        
        // Find size setting function
        let setSizeAddr = Module.findExportByName(null, setSize_SYMBOL_NAME);
        
        // If not found, try scanning all loaded modules
        if (!setSizeAddr) {
            sendEvent("function_search_start", {
                message: "Searching for QgsMapSettings::setOutputSize function..."
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
                        const symbol = module.findExportByName(setSize_SYMBOL_NAME);
                        if (symbol) {
                            setSizeAddr = symbol;
                        }
                    }
                },
                onComplete: function() {}
            });
            
            // If still not found, report error
            if (!setSizeAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "Cannot find QgsMapSettings::setOutputSize function"
                });
                return;
            }
        }
        
        // Report function found
        sendEvent("setSize_function_found", {
            address: setSizeAddr.toString(),
            message: "Found QgsMapSettings::setOutputSize function"
        });
        
        // Install hook - Set path
        Interceptor.attach(setPathAddr, {
            onLeave: function(retval) {
                try {
                    // QFileDialog::getSaveFileName returns a QString
                    const pathQString = retval;
                    const filePath = qstringToString(pathQString);
                    
                   
                    console.log("PDF export path:", filePath);
                    
                    // Send event notification
                    sendEvent("PathandType_set", {
                        path: filePath,
                        message: `PDF export settings detected: Path=${filePath}`
                    });
                } catch (error) {
                    sendEvent("error", {
                        error_type: "hook_execution_error",
                        message: `Error getting path: ${error.message}`,
                        stack: error.stack
                    });
                }
            }
        });
        
        // Install hook - Set size
        Interceptor.attach(setSizeAddr, {
            onEnter: function(args) {
                try {
                    //According to System V AMD64 ABI section 3.2.3, for structures less than or equal to 16 bytes,
                    //if all fields are integers or pointers, the entire structure is divided into one or more 8-byte blocks,
                    //each in the INTEGER class, passed through integer registers.
                    // First convert NativePointer to unsigned 64-bit BigInt
                    // 1. Get hex string, remove "0x" prefix
                    let hex = args[1].toString(16);
                    if (hex.startsWith("0x")) { hex = hex.slice(2); }

                    // 2. Pad to 16 digits (8 bytes) length
                    hex = hex.padStart(16, "0");

                    // 3. High 8 bytes = height, low 8 bytes = width
                    const hi = hex.slice(0, 8);
                    const lo = hex.slice(8);

                    const height = parseInt(hi, 16);
                    const width  = parseInt(lo, 16);
                    
                    console.log("PDF export size: Width=", width, "Height=", height);
                    
                    // Send event notification
                    sendEvent("Size_set", {
                        width: width,
                        height: height,
                        message: `PDF size settings detected: Width=${width}px, Height=${height}px`
                    });
                } catch (error) {
                    sendEvent("error", {
                        error_type: "hook_execution_error",
                        message: `Error getting size: ${error.message}`,
                        stack: error.stack
                    });
                }
            }
        });
        
        sendEvent("hook_installed", {
            message: "Hook installation complete, waiting for PDF export operations..."
        });
    }
    
    // Execute hook initialization immediately
    initHook();
})();