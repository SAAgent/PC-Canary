/**
 * Gets all breakpoints in the current workspace
 * @returns {Promise<Array<{file: string, line: number, condition: string}>>}
 */
async function getAllBreakpoints() {
    const breakpoints = vscode.debug.breakpoints;
    const breakpointDetails = [];

    for (const bp of breakpoints) {
        if (bp instanceof vscode.SourceBreakpoint) {
            const location = bp.location;
            breakpointDetails.push({
                file: location.uri.fsPath,
                line: location.range.start.line + 1, // VS Code lines are 0-based
                condition: bp.condition || ''
            });
        }
    }

    return breakpointDetails;
}

/**
 * Recursively fetches variables and their values
 * @param {vscode.DebugSession} session - The active debug session
 * @param {number} variablesReference - Reference to the variables
 * @param {string} parentName - Name of the parent variable (for nested display)
 * @returns {Promise<Array<{name: string, value: string}>>}
 */
async function fetchVariables(session, variablesReference, parentName = '') {
    if (variablesReference <= 0) {
        return [];
    }

    try {
        const variablesResponse = await session.customRequest('variables', { variablesReference });
        const variables = variablesResponse?.variables || [];
        const result = [];

        for (const variable of variables) {
            const varName = parentName ? `${parentName}.${variable.name}` : variable.name;
            let varValue = variable.value;

            // If the variable has a reference (e.g., object, array, std::vector), fetch its children
            if (variable.variablesReference > 0 && variable.value === '{...}') {
                const childVariables = await fetchVariables(session, variable.variablesReference, varName);
                if (childVariables.length > 0) {
                    result.push(...childVariables);
                } else {
                    // Fallback to the original value if no children are found
                    result.push({ name: varName, value: varValue });
                }
            } else {
                result.push({ name: varName, value: varValue });
            }
        }

        return result;
    } catch (error) {
        console.error(`Error fetching variables for reference ${variablesReference}:`, error);
        return [];
    }
}

/**
 * Gets information about the current debug session
 * @returns {Promise<{file: string, line: number, locals: Array<{name: string, value: string}>} | null>}
 */
async function getCurrentDebugSessionInfo() {
    const activeSession = vscode.debug.activeDebugSession;
    if (!activeSession) {
        console.log('No active debug session found');
        return null;
    }

    try {
        // Get threads
        const threadsResponse = await activeSession.customRequest('threads');
        const threadId = threadsResponse?.threads[0]?.id;
        if (!threadId) {
            console.log('No threads found in debug session');
            return null;
        }

        // Get stack frames
        const stackFramesResponse = await activeSession.customRequest('stackTrace', { threadId });
        const stackFrames = stackFramesResponse?.stackFrames;
        if (!stackFrames || stackFrames.length === 0) {
            console.log('No stack frames available');
            return null;
        }

        const topFrame = stackFrames[0];
        const sourcePath = topFrame.source?.path || 'Unknown';

        // Get scopes for the top frame
        const scopesResponse = await activeSession.customRequest('scopes', { frameId: topFrame.id });
        const scopes = scopesResponse?.scopes;
        if (!scopes || scopes.length === 0) {
            console.log('No scopes found for the current frame');
            return null;
        }

        // Collect local variables
        const locals = [];
        for (const scope of scopes) {
            if (scope.name === 'Locals' && scope.variablesReference > 0) {
                const scopeVariables = await fetchVariables(activeSession, scope.variablesReference);
                locals.push(...scopeVariables);
            }
        }

        return {
            file: sourcePath,
            line: topFrame.line,
            locals
        };
    } catch (error) {
        console.error('Error retrieving debug session info:', error);
        return null;
    }
}

// Listen for 'evaluate' event
socket.on('evaluate', async () => {
    const breakpoint_info = await getAllBreakpoints();
    const debug_session_info = await getCurrentDebugSessionInfo();
    // vscode.window.showInformationMessage(message);
    socket.emit("send", {
        'event_type': "evaluate_on_completion",
        'message': "任务结束时获取到debug会话的状态",
        'breakpoints': breakpoint_info,
        'debuginfo': debug_session_info
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
                    'condition': breakpoint.condition || '',
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
                    'condition': breakpoint.condition || '',
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
                    'condition': breakpoint.condition || '',
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