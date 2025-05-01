/**
 * Gets the root directory of the current workspace.
 * @returns {string | undefined} The workspace root directory path or undefined if no workspace is open.
 */
async function getWorkspaceRoot() {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (workspaceFolders && workspaceFolders.length > 0) {
        // Return the first workspace folder's path
        return workspaceFolders[0].uri.fsPath;
    }
    return undefined;
}

getWorkspaceRoot().then(root => {
    socket.emit("send", {
        'event_type': "get_origin_file",
        'message': "在任务开始时获取文件的全部内容",
        'root': root
    });
});

/**
 * Gets the file path of the currently displayed file in the active editor.
 * @returns {string | null} The file path of the active file, or null if no file is displayed.
 */
async function getActiveFile() {
    try {
        // Get the active text editor
        const activeEditor = vscode.window.activeTextEditor;
        if (!activeEditor) {
            return null; // No active editor
        }

        // Get the document from the active editor
        const document = activeEditor.document;
        if (document.uri.scheme === 'file') {
            return document.fileName; // Return absolute file path
        }
        return null; // Not a file-based document
    } catch (error) {
        throw new Error(`Error getting active file: ${error.message}`);
    }
}

socket.on('evaluate', async () => {
    const root = await getWorkspaceRoot();
    const filename = await getActiveFile();
    // vscode.window.showInformationMessage(message);
    socket.emit("send", {
        'event_type': "evaluate_on_completion",
        'message': "任务结束时检查任务是否完成",
        'root': root,
        'filename': filename
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