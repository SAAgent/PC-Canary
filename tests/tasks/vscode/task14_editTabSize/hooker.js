/**
 * Reads the .vscode/settings.json file from the current workspace and returns its contents as a JSON object.
 * Returns an empty object if the file does not exist or is invalid.
 * @returns {Promise<object>} The JSON contents of settings.json or an empty object
 */
async function readWorkspaceSettings() {
    try {
        // Get the workspace folders
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders || workspaceFolders.length === 0) {
            return {};
        }
        
        // Use the first workspace folder (multi-root workspaces would need additional handling)
        const workspacePath = workspaceFolders[0].uri;
        // vscode.window.showInformationMessage(workspacePath);
        const settingsFileUri = vscode.Uri.joinPath(workspacePath, '.vscode', 'settings.json');

        // Read the file
        const fileContent = await vscode.workspace.fs.readFile(settingsFileUri);
        const fileContentString = Buffer.from(fileContent).toString('utf8');

        // Parse JSON
        return JSON.parse(fileContentString);
    } catch (error) {
        // Return empty object if file doesn't exist or is invalid
        if (error instanceof vscode.FileSystemError && error.code === 'FileNotFound') {
            return {};
        }
        // Handle JSON parse errors or other issues
        return {};
    }
}

// vscode.window.showInformationMessage(`代码成功注入`);
readWorkspaceSettings().then(settings => {
    socket.emit("send", {
        'event_type': "read_origin_content",
        'message': "任务开始时读取settings.json文件内容",
        'data': settings
    });
});

// Listen for 'evaluate' event
socket.on('evaluate', async () => {
    const settings = await readWorkspaceSettings();
    // vscode.window.showInformationMessage(message);
    socket.emit("send", {
        'event_type': "evaluate_on_completion",
        'message': "任务结束时读取文件内容",
        'data': settings
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