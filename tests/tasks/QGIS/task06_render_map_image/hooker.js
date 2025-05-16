// QGIS Map Image Export Hook Script
// Used to monitor QGIS map image export operations and detect related parameters

(function() {
    // Script constants
    const setPathandType_SYMBOL_NAME="_ZN11QgsGuiUtils18getSaveAsImageNameEP7QWidgetRK7QStringS4_" // QgsGuiUtils::getSaveAsImageName function symbol
    const setPathandType_SYMBOL_NAME2="_ZNK6QImage4saveERK7QStringPKci" // QImage::save function symbol
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
            message: "QGIS map image export monitoring script started"
        });
        
        // Find path and type setting function
        let setPathandTypeAddr = Module.findExportByName(null, setPathandType_SYMBOL_NAME);
        
        // If not found, try scanning all loaded modules
        if (!setPathandTypeAddr) {
            sendEvent("function_search_start", {
                message: "Searching for QgsGuiUtils::getSaveAsImageName function..."
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
                        const symbol = module.findExportByName(setPathandType_SYMBOL_NAME);
                        if (symbol) {
                            setPathandTypeAddr = symbol;
                        }
                    }
                },
                onComplete: function() {}
            });
            
            // If still not found, report error
            if (!setPathandTypeAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "Cannot find QgsGuiUtils::getSaveAsImageName function"
                });
            }
        }
        
        // If first function found, report and install hook
        if (setPathandTypeAddr) {
            // Report function found
            sendEvent("setPathandType_function_found", {
                address: setPathandTypeAddr.toString(),
                message: "Found QgsGuiUtils::getSaveAsImageName function"
            });
            
            // Install hook - Set path and type
            Interceptor.attach(setPathandTypeAddr, {
                onLeave: function(retval) {
                    try {
                        // Get QPair<QString, QString> return value
                        const pairPtr = retval;
                        
                        // Read first QString - file path
                        const pathQString = pairPtr;
                        const filePath = qstringToString(pathQString);
                        
                        // Read second QString - file type
                        const typeQString = pairPtr.add(Process.pointerSize); // QString size is typically 4x pointer size
                        const fileType = qstringToString(typeQString);
                        
                        console.log("Image export path:", filePath, "type:", fileType);
                        
                        // Send event notification
                        sendEvent("PathandType_set", {
                            path: filePath,
                            type: fileType,
                            message: `Image export settings detected: Path=${filePath}, Type=${fileType}`
                        });
                    } catch (error) {
                        sendEvent("error", {
                            error_type: "hook_execution_error",
                            message: `Error getting path and type: ${error.message}`,
                            stack: error.stack
                        });
                    }
                }
            });
        }
        
        // Find QImage::save function
        let imageSaveAddr = Module.findExportByName(null, setPathandType_SYMBOL_NAME2);
        
        // If not found, try scanning all loaded modules
        if (!imageSaveAddr) {
            sendEvent("function_search_start", {
                message: "Searching for QImage::save function..."
            });
            
            // Enumerate modules
            Process.enumerateModules({
                onMatch: function(module) {
                    if (module.name.includes("Qt5")) {
                        sendEvent("module_found", {
                            module_name: module.name,
                            base_address: module.base.toString()
                        });
                        
                        // Search for symbol in Qt5 module
                        const symbol = module.findExportByName(setPathandType_SYMBOL_NAME2);
                        if (symbol) {
                            imageSaveAddr = symbol;
                        }
                    }
                },
                onComplete: function() {}
            });
            
            // If still not found, report error
            if (!imageSaveAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "Cannot find QImage::save function"
                });

            }
        }
        
        // If QImage::save function found, report and install hook
        if (imageSaveAddr) {
            // Report function found
            sendEvent("image_save_function_found", {
                address: imageSaveAddr.toString(),
                message: "Found QImage::save function"
            });
            
            // Install hook - QImage::save
            Interceptor.attach(imageSaveAddr, {
                onEnter: function(args) {
                    try {
                        // Get first parameter - file path (const QString &fileName)
                        const pathQString = args[1];
                        const filePath = qstringToString(pathQString);
                        
                        // Get extension from file path as type
                        let fileType = "";
                        const lastDotIndex = filePath.lastIndexOf('.');
                        if (lastDotIndex !== -1 && lastDotIndex < filePath.length - 1) {
                            fileType = filePath.substring(lastDotIndex + 1).toLowerCase();
                        }
                        
                        console.log("QImage saving image path:", filePath, "type:", fileType);
                        
                        // Send event notification
                        sendEvent("PathandType_set", {
                            path: filePath,
                            type: fileType,
                            message: `QImage save image detected: Path=${filePath}, Type=${fileType}`
                        });
                    } catch (error) {
                        sendEvent("error", {
                            error_type: "hook_execution_error",
                            message: `Error getting QImage::save path and type: ${error.message}`,
                            stack: error.stack
                        });
                    }
                }
            });
        }
        
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
                    
                    console.log("Image export size: Width=", width, "Height=", height);
                    
                    // Send event notification
                    sendEvent("Size_set", {
                        width: width,
                        height: height,
                        message: `Image size settings detected: Width=${width}px, Height=${height}px`
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
            message: "Hook installation complete, waiting for map export operations..."
        });
    }
    
    // Execute hook initialization immediately
    initHook();
})();