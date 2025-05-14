// 使用 Joplin 插件 API 来处理通信
joplin.plugins.register({
    onStart: async function() {
        console.log('Joplin plugin started');
        
        // 主题值映射
        const themeMap = {
            '1': 'Light',
            '2': 'Dark',
            '3': 'Sepia'
        };

        // 监听 evaluate 事件
        socket.on("evaluate", async () => {
            console.log('Task01_updateColorTheme---------------------------');
            try {
                // 获取当前主题
                const themeValue = await joplin.settings.globalValue('theme');
                const currentTheme = themeMap[themeValue] || 'Unknown';
                console.log('Current theme value:', themeValue, 'mapped to:', currentTheme);
                
                // 使用 postMessage 发送评估消息
                window.postMessage({
                    "event_type": "evaluate_on_completion",
                    "message": "任务结束时Joplin的主题颜色是" + currentTheme,
                    "data": currentTheme
                }, '*');
                console.log('Evaluation result sent via postMessage');
            } catch (error) {
                console.error('Error in evaluate handler:', error);
            }
        });
    }
}); 