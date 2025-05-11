// 使用 Joplin 插件 API 来处理通信
joplin.plugins.register({
    onStart: async function() {
        console.log('Joplin plugin started');
        
        // 监听 evaluate 事件
        socket.on("evaluate", async () => {
            console.log('Task17_restoreNote---------------------------');
            try {
                // 获取所有笔记（包括已删除的笔记）
                const notes = await joplin.data.get(['notes'], {
                    fields: ['id', 'title', 'deleted_time']
                });
                const noteList = notes.items;
                
                // 分离当前笔记和已删除笔记
                const currentNotes = noteList
                    .filter(note => !note.deleted_time)
                    .map(note => note.title);
                
                const deletedNotes = noteList
                    .filter(note => note.deleted_time)
                    .map(note => note.title);
                
                console.log('Current notes:', currentNotes);
                console.log('Deleted notes:', deletedNotes);
                
                // 使用 postMessage 发送评估消息
                window.postMessage({
                    "event_type": "evaluate_on_completion",
                    "message": "当前笔记列表: " + currentNotes.join(', '),
                    "data": {
                        "notes": currentNotes,
                        "deleted_notes": deletedNotes
                    }
                }, '*');
            } catch (error) {
                console.error('Error in evaluate handler:', error);
            }
        });
    }
}); 