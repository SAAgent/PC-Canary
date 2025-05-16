// 使用 Joplin 插件 API 来处理通信
joplin.plugins.register({
    onStart: async function() {
        console.log('Joplin plugin started - Task06 Editor Type');
        
        // 监听 evaluate 事件
        socket.on("evaluate", async () => {
            console.log('Task06_updateEditorType---------------------------');
            try {
                let currentEditorType = 'markdown'; // 默认值
                
                // 尝试获取编辑器相关设置
                try {
                    // 检查是否启用了富文本编辑器
                    // 在 Joplin 中，editor.codeView 控制是否显示代码视图
                    // false 表示使用富文本/WYSIWYG 编辑器，true 表示使用 Markdown 编辑器
                    const codeViewEnabled = await joplin.settings.globalValue('editor.codeView');
                    
                    console.log('Code view enabled:', codeViewEnabled);
                    
                    // 根据设置判断当前编辑器类型
                    if (codeViewEnabled === false) {
                        currentEditorType = 'richtext';
                    } else {
                        currentEditorType = 'markdown';
                    }
                } catch (settingsError) {
                    console.error('Error reading editor settings:', settingsError);
                    
                    // 备用方案：检查当前活动的编辑器元素
                    const editorElement = document.querySelector('.ql-editor, .richtext-editor, .cm-editor');
                    if (editorElement && (editorElement.classList.contains('ql-editor') || editorElement.classList.contains('richtext-editor'))) {
                        currentEditorType = 'richtext';
                    }
                }
                
                console.log('Current editor type:', currentEditorType);
                
                // 使用 postMessage 发送评估消息
                window.postMessage({
                    "event_type": "evaluate_on_completion",
                    "message": "任务结束时Joplin的编辑器类型是" + currentEditorType,
                    "data": currentEditorType
                }, '*');
                console.log('Evaluation result sent via postMessage');
            } catch (error) {
                console.error('Error in evaluate handler:', error);
            }
        });
    }
});