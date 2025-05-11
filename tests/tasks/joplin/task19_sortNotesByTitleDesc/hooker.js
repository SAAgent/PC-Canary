// 使用 Joplin 插件 API 来处理通信
joplin.plugins.register({
    onStart: async function() {
        console.log('Joplin plugin started');
        // 监听 evaluate 事件
        socket.on("evaluate", async () => {
            console.log('Task19_sortNotesByTitleDesc---------------------------');
            try {
                // Joplin官方API没有直接获取当前排序方式的接口
                // 但可以通过settings获取相关设置
                let sortField = null;
                let sortOrder = null;
                try {
                    sortField = await joplin.settings.globalValue('notes.sortOrder.field');
                    sortOrder = await joplin.settings.globalValue('notes.sortOrder.reverse');
                } catch (e) {
                    // 某些Joplin版本可能没有这些设置
                    console.warn('无法通过settings获取排序方式:', e);
                }
                // 兼容Joplin的排序设置
                // sortField 可能为 'title', sortOrder 可能为 true(倒序) 或 false(正序)
                let sortFieldStr = sortField || 'unknown';
                let sortOrderStr = (sortOrder === true || sortOrder === 1 || sortOrder === '1') ? 'desc' : 'asc';
                // 使用 postMessage 发送评估消息
                window.postMessage({
                    "event_type": "evaluate_on_completion",
                    "message": `当前排序方式: 字段=${sortFieldStr}, 顺序=${sortOrderStr}`,
                    "data": {
                        "sort_field": sortFieldStr,
                        "sort_order": sortOrderStr
                    }
                }, '*');
            } catch (error) {
                console.error('Error in evaluate handler:', error);
                window.postMessage({
                    "event_type": "evaluate_on_completion",
                    "message": "无法获取当前排序方式，Joplin API未提供相关接口",
                    "data": {
                        "sort_field": "unknown",
                        "sort_order": "unknown"
                    }
                }, '*');
            }
        });
    }
}); 