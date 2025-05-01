/**
 * 检查当前打开的文件是否含有错误提示，并返回文件名和文件内容（包括未保存的修改）
 * @returns {Promise<{hasErrors: boolean, fileName: string | null, content: string | null}>} 返回对象包含错误状态、文件名和文件内容
 */
async function hasFileErrors() {
    // 获取当前活动编辑器
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showInformationMessage('No active editor found.');
        return { hasErrors: false, fileName: null, content: null };
    }

    // 获取当前文件的 URI、文件名和内容
    const fileUri = editor.document.uri;
    const fileName = editor.document.fileName;
    const content = editor.document.getText(); // 获取当前文档内容，包括未保存的修改

    // 获取文件的诊断信息
    const diagnostics = vscode.languages.getDiagnostics(fileUri);

    // 检查是否有错误
    const hasErrors = diagnostics.some(diagnostic => 
        diagnostic.severity === vscode.DiagnosticSeverity.Error
    );

    return { hasErrors, fileName, content };
}

socket.on('evaluate', async () => {
    const hasErrors = await hasFileErrors();
    // vscode.window.showInformationMessage(message);
    socket.emit("send", {
        'event_type': "evaluate_on_completion",
        'message': "任务结束时检查打开的文件是否含有报错",
        'hasErrors': hasErrors
    });
});