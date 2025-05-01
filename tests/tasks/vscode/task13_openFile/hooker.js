/**
 * 异步获取当前光标所在文件的名称和行号
 * @returns {Promise<{fileName: string, lineNumber: number} | null>} 文件信息对象或null
 */
async function getFileAndLineInfo() {
    const editor = vscode.window.activeTextEditor;
    
    if (!editor) {
        return null;
    }
    
    const filePath = editor.document.fileName;
    const fileName = filePath.split(/[\\/]/).pop();
    const lineNumber = editor.selection.active.line + 1;
    
    return { fileName, lineNumber };
}

// Listen for 'evaluate' event
socket.on('evaluate', async () => {
    const info = await getFileAndLineInfo();
    // vscode.window.showInformationMessage(message);
    socket.emit("send", {
        'event_type': "evaluate_on_completion",
        'message': "任务结束时获得光标的位置",
        'info': info
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