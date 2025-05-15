/**
 * Inspects the current C++ debug session and returns breakpoint and stop location information
 * @returns {Promise<{breakpoints: Array, currentFile: string, currentLine: string}> | null} Debug information or null if invalid session
 */
async function inspectCppDebugSession() {
    try {
        // Get all breakpoints
        const breakpoints = vscode.debug.breakpoints;
        let breakpointDetails = [];
        
        for (const bp of breakpoints) {
            if (bp instanceof vscode.SourceBreakpoint) {
                const location = bp.location;
                breakpointDetails.push({
                    file: location.uri.fsPath,
                    line: location.range.start.line + 1,
                    enabled: bp.enabled,
                    condition: bp.condition || 'None'
                });
            }
        }

        return breakpointDetails;
    } catch (error) {
        socket.emit("send", {
            'event_type': "error",
            'message': `在获取debug会话时出现错误: ${error}`
        });
        console.error('Inspection error:', error);
        throw error;
    }
}

// Listen for 'evaluate' event
socket.on('evaluate', async () => {
    const breakpoints = await inspectCppDebugSession();
    // vscode.window.showInformationMessage(message);
    socket.emit("send", {
        'event_type': "evaluate_on_completion",
        'message': "在任务结束时检查断点信息",
        'breakpoints': breakpoints
    });
});

// Register a listener for when a text document is opened
vscode.workspace.onDidOpenTextDocument(async (document) => {
    const filePath = document.uri.fsPath;
    socket.emit("send", {
        event_type: "open_file",
        message: "打开文件",
        path: filePath,
        scheme: document.uri.scheme
    });
});