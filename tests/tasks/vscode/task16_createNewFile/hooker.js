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

socket.on('evaluate', async () => {
    const root = await getWorkspaceRoot();
    // vscode.window.showInformationMessage(message);
    socket.emit("send", {
        'event_type': "evaluate_on_completion",
        'message': "任务结束时检查文件是否存在",
        'root': root
    });
});