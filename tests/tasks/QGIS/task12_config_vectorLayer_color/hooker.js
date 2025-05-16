// QGIS Vector Layer Color Configuration Hook Script
// Used to monitor QGIS vector layer color setting operations and detect related parameters

(function() {
    // Script constants setup
    const SYMBOL_NAME = "_ZN20QgsSymbolsListWidget14setSymbolColorERK6QColor"; // QgsSymbolsListWidget::setSymbolColor function symbol
    
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
    // Convert QColor to hex string
    function qColorToHex(r, g, b) {
        const toHex = (val) => 
            Math.round( (val/65535)*255 )
                .toString(16)
                .padStart(2, '0')
                .toUpperCase()
        
        return `#${toHex(r)}${toHex(g)}${toHex(b)}`
    }

    // Initialize hook and execute immediately
    function initHook() {
        sendEvent("script_initialized", {
            message: "QGIS vector layer color configuration monitoring script has started"
        });
        
        // Find setSymbolColor function
        let setColorAddr = Module.findExportByName(null, SYMBOL_NAME);
        
        // If not found, try scanning all loaded modules
        if (!setColorAddr) {
            sendEvent("function_search_start", {
                message: "Searching for QgsSymbolsListWidget::setSymbolColor function..."
            });
            
            // Enumerate modules
            Process.enumerateModules({
                onMatch: function(module) {
                    if (module.name.includes("qgis_gui")) {
                        sendEvent("module_found", {
                            module_name: module.name,
                            base_address: module.base.toString()
                        });
                        
                        // Find symbol in qgis_gui module
                        const symbol = module.findExportByName(SYMBOL_NAME);
                        if (symbol) {
                            setColorAddr = symbol;
                        }
                    }
                },
                onComplete: function() {}
            });
            
            // If still not found, report error
            if (!setColorAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "Unable to find QgsSymbolsListWidget::setSymbolColor function"
                });
                return;
            }
        }
        
        // Report function found
        sendEvent("set_function_found", {
            address: setColorAddr.toString(),
            message: "Found QgsSymbolsListWidget::setSymbolColor function"
        });
        
        // Install hook
        Interceptor.attach(setColorAddr, {
            onEnter: function(args) {
                try {
                    // Get this pointer, read layer name
                    const thisPtr = args[0];
                    // Layer name is at this+0x1f0 readpointer then +0x20
                    const layerPtr = thisPtr.add(0x1f0).readPointer();
                    const nameQString = layerPtr.add(0x20);
                    const layerName = qstringToString(nameQString);
                    
                    console.log("Setting layer color, layer name:", layerName);
                    
                    // Send layer name event
                    sendEvent("layer_set", {
                        name: layerName,
                        message: `Detected layer for color setting, name: ${layerName}`
                    });
                    
                    // Get color parameters (QColor)
                    const colorPtr = args[1];
                    // Read RGBA values
                    const alpha = colorPtr.add(0x4).readU16();
                    const red = colorPtr.add(0x6).readU16();
                    const green = colorPtr.add(0x8).readU16();
                    const blue = colorPtr.add(0xa).readU16();
                    
                    // Convert to hex representation
                    const hexColor = qColorToHex(red, green, blue);
                    
                    console.log("Setting color to:", hexColor, "RGBA:", red, green, blue, alpha);
                    
                    // Send color event
                    sendEvent("color_set", {
                        layer: layerName,
                        color: hexColor,
                        rgba: {
                            red: red,
                            green: green,
                            blue: blue,
                            alpha: alpha
                        },
                        message: `Detected color setting for layer ${layerName}: ${hexColor}`
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
            message: "Hook installation completed, waiting for layer color setting operations..."
        });
    }
    
    // Execute hook initialization immediately
    initHook();
})();