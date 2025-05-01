/**
 * Inspects the current C++ debug session and returns breakpoint and stop location information
 * @returns {Promise<{breakpoints: Array, currentFile: string, currentLine: string}> | null} Debug information or null if invalid session
 */
async function inspectCppDebugSession() {
    try {
        // Check if C/C++ extension is installed
        const cpptoolsExtension = vscode.extensions.getExtension('ms-vscode.cpptools');
        if (!cpptoolsExtension) {
            throw new Error('C/C++ extension (ms-vscode.cpptools) is not installed');
        }

        // Check if a debug session is active
        if (!vscode.debug.activeDebugSession) {
            throw new Error('No active debug session found');
        }

        // Verify if the debug session is using cpptools
        const debugType = vscode.debug.activeDebugSession.type;
        if (debugType !== 'cppdbg' && debugType !== 'cppvsdbg') {
            throw new Error('Current debug session is not using C/C++ debugger');
        }

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

        // Get current stack frame to determine stopped location
        let currentLine = 'Unknown';
        let currentFile = 'Unknown';
        
        try {
            // First, check if the session is stopped
            const threads = await vscode.debug.activeDebugSession.customRequest('threads');
            if (threads && threads.threads && threads.threads.length > 0) {
                // Get the first stopped thread
                const stoppedThread = threads.threads.find(thread => thread.id);
                if (stoppedThread) {
                    const stackFrames = await vscode.debug.activeDebugSession.customRequest('stackTrace', {
                        threadId: stoppedThread.id,
                        startFrame: 0,
                        levels: 1
                    });
                    
                    if (stackFrames.stackFrames && stackFrames.stackFrames.length > 0) {
                        const topFrame = stackFrames.stackFrames[0];
                        currentLine = topFrame.line;
                        currentFile = topFrame.source?.path || 'Unknown';
                    } else {
                        console.log('No stack frames available');
                    }
                } else {
                    console.log('No stopped threads found');
                }
            } else {
                console.log('No threads available');
            }
        } catch (error) {
            console.error('Error fetching stack trace:', error);
        }

        return {
            breakpoints: breakpointDetails,
            currentFile,
            currentLine
        };
    } catch (error) {
        socket.emit("send", {
            'event_type': "error",
            'message': "在获取debug会话时出现错误"
        });
        console.error('Inspection error:', error);
        throw error;
    }
}

// Listen for 'evaluate' event
socket.on('evaluate', async () => {
    const debugInfo = await inspectCppDebugSession();
    // vscode.window.showInformationMessage(message);
    socket.emit("send", {
        'event_type': "evaluate_on_completion",
        'message': "任务结束时获取到debug会话的状态",
        'breakpoints': debugInfo.breakpoints,
        'current_file': debugInfo.currentFile,
        'current_line': debugInfo.currentLine
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

// Register a listener for when breakpoints change
vscode.debug.onDidChangeBreakpoints((event) => {
    try {
        // Process added breakpoints
        event.added.forEach((breakpoint) => {
            if (breakpoint instanceof vscode.SourceBreakpoint) {
                const location = breakpoint.location;
                socket.emit('send', {
                    'event_type': 'breakpoint_change',
                    'message': '断点添加',
                    'action': 'added',
                    'path': location.uri.fsPath,
                    'line': location.range.start.line + 1, // Convert to 1-based line number
                    'condition': breakpoint.condition || 'None',
                    'enabled': breakpoint.enabled
                });
            }
        });

        // Process removed breakpoints
        event.removed.forEach((breakpoint) => {
            if (breakpoint instanceof vscode.SourceBreakpoint) {
                const location = breakpoint.location;
                socket.emit('send', {
                    'event_type': 'breakpoint_change',
                    'message': '断点移除',
                    'action': 'removed',
                    'path': location.uri.fsPath,
                    'line': location.range.start.line + 1,
                    'condition': breakpoint.condition || 'None',
                    'enabled': breakpoint.enabled
                });
            }
        });

        // Process changed breakpoints
        event.changed.forEach((breakpoint) => {
            if (breakpoint instanceof vscode.SourceBreakpoint) {
                const location = breakpoint.location;
                socket.emit('send', {
                    'event_type': 'breakpoint_change',
                    'message': '断点修改',
                    'action': 'changed',
                    'path': location.uri.fsPath,
                    'line': location.range.start.line + 1,
                    'condition': breakpoint.condition || 'None',
                    'enabled': breakpoint.enabled
                });
            }
        });

        console.log(`Breakpoints changed: added=${event.added.length}, removed=${event.removed.length}, changed=${event.changed.length}`);
    } catch (error) {
        console.error(`Error handling breakpoint change: ${error.message}`);
    }
});

vscode.debug.onDidStartDebugSession((session) => {
    try {
        // Get the program path and working directory from the configuration
        const program = session.configuration.program || 'unknown';
        const cwd = session.configuration.cwd || session.workspaceFolder?.uri.fsPath || 'unknown';

        // Emit debug session start event via socket
        socket.emit('send', {
            'event_type': 'debug_session_start',
            'message': '调试会话开始',
            'session_name': session.name,
            'debugger_type': session.type,
            'program': program,
            'working_dir': cwd
        });

        console.log(`Debug session started: name=${session.name}, type=${session.type}, program=${program}`);
    } catch (error) {
        console.error(`Error handling debug session start: ${error.message}`);
    }
});