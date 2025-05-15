/**
 * 获取当前打开的文件和拆分窗口信息
 * @returns {Promise<Object>} 包含打开文件和拆分窗口信息的对象
 */
async function getOpenFilesAndSplits() {
    try {
        // 获取当前打开的文件
        const activeEditor = vscode.window.activeTextEditor;
        const activeFile = activeEditor ? activeEditor.document.uri.fsPath : 'No active file';

        // 获取所有打开的编辑器（包括非激活的）
        const openFiles = vscode.window.visibleTextEditors.map(editor => ({
            filePath: editor.document.uri.fsPath,
            isActive: editor === activeEditor
        }));

        // 获取拆分窗口信息
        const tabGroups = vscode.window.tabGroups.all;
        const splitInfo = tabGroups.map((group, index) => ({
            groupId: index + 1,
            isActive: group.activeTab ? true : false,
            tabs: group.tabs.map(tab => ({
                label: tab.label,
                filePath: tab.input instanceof vscode.TabInputText ? tab.input.uri.fsPath : 'Unknown',
                isActive: tab === group.activeTab
            }))
        }));

        return {
            activeFile,
            openFiles,
            splitInfo
        };
    } catch (error) {
        throw new Error(`Failed to get files and splits: ${error.message}`);
    }
}

// Listen for 'evaluate' event
socket.on('evaluate', async () => {
    const info = await getOpenFilesAndSplits();
    // vscode.window.showInformationMessage(message);
    socket.emit("send", {
        'event_type': "evaluate_on_completion",
        'message': "任务结束时获得打开文件的信息",
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