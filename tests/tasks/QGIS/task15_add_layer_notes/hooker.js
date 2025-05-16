// QGIS Layer Notes Addition Hook Script
// Used to monitor QGIS layer notes addition operations and detect related parameters

(function () {
    // Script constants setup
    const SYMBOL_NAME = "_ZN18QgsLayerNotesUtils13setLayerNotesEP11QgsMapLayerRK7QString"; // QgsLayerNotesUtils::setLayerNotes function symbol

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
    
    // Extract plain text content from HTML
    function extractTextFromHtml(html) {
        try {
            // Extract content from <p> tags
            const matches = html.match(/<p[^>]*>(.*?)<\/p>/g);
            if (matches && matches.length > 0) {
                // Extract text from all <p> tags and merge
                const textContents = matches.map(p => {
                    // Remove all HTML tags
                    return p.replace(/<[^>]*>/g, '');
                });
                return textContents.join("\n");
            }
            
            // If no <p> tags found, remove all tags and return plain text
            return html.replace(/<[^>]*>/g, '');
        } catch (error) {
            console.log("Failed to extract text:", error);
            return html;
        }
    }

    // Initialize hook and execute immediately
    function initHook() {
        sendEvent("script_initialized", {
            message: "QGIS layer notes monitoring script has started"
        });

        // Find setLayerNotes function
        let setNotesAddr = Module.findExportByName(null, SYMBOL_NAME);

        // If not found, try scanning all loaded modules
        if (!setNotesAddr) {
            sendEvent("function_search_start", {
                message: "Searching for QgsLayerNotesUtils::setLayerNotes function..."
            });

            // Enumerate modules
            Process.enumerateModules({
                onMatch: function (module) {
                    if (module.name.includes("qgis_core")) {
                        sendEvent("module_found", {
                            module_name: module.name,
                            base_address: module.base.toString()
                        });

                        // Find symbol in qgis_core module
                        const symbol = module.findExportByName(SYMBOL_NAME);
                        if (symbol) {
                            setNotesAddr = symbol;
                        }
                    }
                },
                onComplete: function () { }
            });

            // If still not found, report error
            if (!setNotesAddr) {
                sendEvent("error", {
                    error_type: "function_not_found",
                    message: "Unable to find QgsLayerNotesUtils::setLayerNotes function"
                });
                return;
            }
        }

        // Report function found
        sendEvent("set_function_found", {
            address: setNotesAddr.toString(),
            message: "Found QgsLayerNotesUtils::setLayerNotes function"
        });
        
        // Install hook
        Interceptor.attach(setNotesAddr, {
            onEnter: function(args) {
                try {
                    // Get parameters: layer and notes (no this pointer as it's a class call)
                    // args[0] is QgsLayer pointer, args[1] is QString pointer
                    const layerPtr = args[0];  
                    const notesQString = args[1];
                    console.log("Adding layer notes, parameters:", layerPtr);
                    if (!layerPtr.isNull()) {
                        // Get layer name
                        const nameQString = layerPtr.add(0x20);
                        console.log("Layer name pointer:", nameQString);
                        const layerName = qstringToString(nameQString);

                        console.log("Adding layer notes, layer name:", layerName);

                        // Send layer name event
                        sendEvent("layer_set", {
                            name: layerName,
                            message: `Detected layer for notes addition, name: ${layerName}`
                        });
                        
                        // Get notes content
                        const notesHtml = qstringToString(notesQString);
                        const notesText = extractTextFromHtml(notesHtml);
                        
                        console.log("Added notes content:", notesText);
                        console.log("Original HTML:", notesHtml);

                        // Send notes content event
                        sendEvent("notes_set", {
                            layer: layerName,
                            notes: notesText,
                            notes_html: notesHtml,
                            message: `Detected notes addition for layer ${layerName}: ${notesText}`
                        });
                    }
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
            message: "Hook installation completed, waiting for layer notes addition operations..."
        });
    }

    // Execute hook initialization immediately
    initHook();
})();