/**
 * Checks if the current view is a VS Code file comparison (non-Git) and returns the paths of the compared files.
 * @returns {Promise<{ originalPath: string, modifiedPath: string } | null>} The paths of the compared files or null if not in compare mode.
 * @throws {Error} If an error occurs while checking the compare view.
 */
async function checkCompareFiles() {
    try {
        // Get the active text editor
        const activeEditor = vscode.window.activeTextEditor;
        if (!activeEditor) {
            throw new Error('No active editor found.');
        }

        // socket.emit("send", {
        //     'event_type': "get_info",
        //     'message': "任务结束时检查任务是否完成",
        //     'info': vscode.window.visibleTextEditors.map(e => ({
        //         uri: e.document.uri.toString(),
        //         scheme: e.document.uri.scheme,
        //         viewColumn: e.viewColumn
        //     }))
        // });

        // Check if the active editor is part of a diff editor
        // Diff editors typically have a specific structure and may not have a viewColumn
        if (activeEditor.viewColumn === undefined) {
            // Try to access the diff editor model
            const diffEditor = activeEditor;
            const diffModel = diffEditor._documentData?._diffEditorModel;

            if (diffModel) {
                const originalUri = diffModel.original.uri;
                const modifiedUri = diffModel.modified.uri;

                console.log('Diff model found:', {
                    originalUri: originalUri.toString(),
                    modifiedUri: modifiedUri.toString()
                });

                if (originalUri.scheme === 'file' && modifiedUri.scheme === 'file') {
                    const originalPath = originalUri.fsPath;
                    const modifiedPath = modifiedUri.fsPath;

                    if (originalPath && modifiedPath) {
                        return { originalPath, modifiedPath };
                    }
                }
                throw new Error('Invalid file URIs in diff editor.');
            } else {
                // Alternative approach: Check visible editors for diff-like behavior
                const editors = vscode.window.visibleTextEditors;
                let originalPath = '';
                let modifiedPath = '';

                for (const editor of editors) {
                    if (editor.document.uri.scheme === 'file') {
                        if (!originalPath) {
                            originalPath = editor.document.uri.fsPath;
                        } else if (!modifiedPath && editor.document.uri.fsPath !== originalPath) {
                            modifiedPath = editor.document.uri.fsPath;
                        }
                    }
                }

                if (originalPath && modifiedPath) {
                    console.log('Fallback method found paths:', { originalPath, modifiedPath });
                    return { originalPath, modifiedPath };
                }
            }
        }

        console.log('Not in a diff editor view.');
        return null; // Not in a file comparison view
    } catch (error) {
        console.error('Error in checkCompareFiles:', error);
        throw new Error(`Error checking compare files: ${error.message}`);
    }
}

socket.on('evaluate', async () => {
    const info = await checkCompareFiles();
    // vscode.window.showInformationMessage(message);
    socket.emit("send", {
        'event_type': "evaluate_on_completion",
        'message': "任务结束时检查任务是否完成",
        'info': info
    });
});