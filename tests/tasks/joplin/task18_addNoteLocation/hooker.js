// 使用 Joplin 插件 API 来处理通信
joplin.plugins.register({
    onStart: async function() {
        console.log('Joplin plugin started');
        
        // 监听 evaluate 事件
        socket.on("evaluate", async () => {
            console.log('Task18_addNoteLocation---------------------------');
            try {
                // 获取所有笔记
                const notes = await joplin.data.get(['notes']);
                const noteList = notes.items;
                
                // 获取指定笔记的位置信息
                const targetNote = noteList.find(note => note.title === 'test_note');
                let location = {};
                
                if (targetNote) {
                    // 获取笔记的完整信息，包括位置数据
                    const noteData = await joplin.data.get(['notes', targetNote.id], {
                        fields: ['id', 'title', 'latitude', 'longitude']
                    });
                    
                    location = {
                        latitude: noteData.latitude,
                        longitude: noteData.longitude
                    };
                }
                
                console.log('Note location:', location);
                
                // 使用 postMessage 发送评估消息
                window.postMessage({
                    "event_type": "evaluate_on_completion",
                    "message": "当前笔记位置信息：" + JSON.stringify(location),
                    "data": {
                        "location": location
                    }
                }, '*');
            } catch (error) {
                console.error('Error in evaluate handler:', error);
            }
        });
    }
}); 