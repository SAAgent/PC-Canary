// 使用 Joplin 插件 API 来处理通信
joplin.plugins.register({
    onStart: async function() {
        console.log('Joplin plugin started');
        
        // 监听 evaluate 事件
        socket.on("evaluate", async () => {
            console.log('Task05_deleteNote---------------------------');
            try {
                // 获取所有笔记
                const notes = await joplin.data.get(['notes']);
                const noteList = notes.items;
                
                // 获取当前笔记名称
                const currentNoteNames = noteList.map(note => note.title);
                console.log('Current notes:', currentNoteNames);
                
                // 使用 postMessage 发送评估消息
                window.postMessage({
                    "event_type": "evaluate_on_completion",
                    "message": "当前笔记列表: " + currentNoteNames.join(', '),
                    "data": {
                        "notes": currentNoteNames
                    }
                }, '*');
                console.log('Evaluation result sent via postMessage');
            } catch (error) {
                console.error('Error in evaluate handler:', error);
            }
        });
    }
}); 