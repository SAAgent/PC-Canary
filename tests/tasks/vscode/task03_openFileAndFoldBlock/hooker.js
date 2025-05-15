/**
 * Checks if a file is open and if all its code blocks are folded
 * @returns {Promise<{isFileOpen: boolean, fileName: string | null, areAllBlocksFolded: boolean}>}
 */
async function checkFileStatus() {
    let isFileOpen = false;
    let fileName = null;
    let areAllBlocksFolded = false;

    // Check if any file is currently open
    const activeEditor = vscode.window.activeTextEditor;
    if (activeEditor) {
        isFileOpen = true;
        fileName = activeEditor.document.fileName; // Get only the file name

        // Get folding ranges for the document
        const foldingRanges = await vscode.commands.executeCommand(
            'vscode.executeFoldingRangeProvider',
            activeEditor.document.uri
        );

        if (foldingRanges && foldingRanges.length > 0) {
            areAllBlocksFolded = true; // Assume all folded until proven otherwise

            for (const range of foldingRanges) {
                // Check if any line in the folding range (beyond start) is visible
                for (let line = range.start + 1; line <= range.end; line++) {
                    const isLineVisible = activeEditor.visibleRanges.some(visibleRange =>
                        line >= visibleRange.start.line && line <= visibleRange.end.line
                    );

                    // If any line in the folding range is visible, the range is not folded
                    if (isLineVisible) {
                        areAllBlocksFolded = false;
                        break;
                    }
                }

                if (!areAllBlocksFolded) {
                    break; // No need to check further ranges
                }
            }
        } else {
            // If no folding ranges exist, consider all blocks folded (vacuous truth)
            areAllBlocksFolded = true;
        }
    }

    return { isFileOpen, fileName, areAllBlocksFolded };
}

// vscode.window.showInformationMessage(`代码成功注入`);

// Listen for 'evaluate' event
socket.on('evaluate', async () => {
    const { isFileOpen, fileName, areAllBlocksFolded } = await checkFileStatus();
    let message1 = isFileOpen ? `${fileName}文件被成功打开` : `没有文件被打开`;
    let message2 = areAllBlocksFolded ? `所有的代码块都被成功折叠` : `代码块没有被成功折叠`;
    // vscode.window.showInformationMessage(message1);
    // vscode.window.showInformationMessage(message2);
    socket.emit("send", {
        'event_type': "evaluate_on_completion",
        'message': message1+`, `+message2,
        'isFileOpen': isFileOpen,
        'fileName': fileName,
        'areBlockFolded': areAllBlocksFolded
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