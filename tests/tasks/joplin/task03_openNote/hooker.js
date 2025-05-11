// 使用 Joplin 插件 API 来处理通信
joplin.plugins.register({
    onStart: async function() {
        console.log('Task03_openNote---------------------------');
        
        // 监听 evaluate 事件
        socket.on("evaluate", async () => {
            try {
                // 获取当前选中的笔记ID
                const selectedNoteIds = await joplin.workspace.selectedNoteIds();
                
                if (selectedNoteIds.length === 0) {
                    console.log('No note is currently selected');
                    window.postMessage({
                        "event_type": "evaluate_on_completion",
                        "message": "当前没有打开的笔记",
                        "data": null
                    }, '*');
                    return;
                }

                // 获取当前笔记的详细信息
                const currentNoteId = selectedNoteIds[0];
                const note = await joplin.data.get(['notes', currentNoteId]);
                console.log('Current note:', note.title);
                
                // 使用 postMessage 发送评估消息
                window.postMessage({
                    "event_type": "evaluate_on_completion",
                    "message": "当前打开的笔记是: " + note.title,
                    "data": note.title
                }, '*');
                console.log('Evaluation result sent via postMessage');
            } catch (error) {
                console.error('Error in evaluate handler:', error);
            }
        });
    }
});