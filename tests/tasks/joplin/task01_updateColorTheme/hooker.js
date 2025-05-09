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

        // 发送消息到评估系统
        function sendEvaluationMessage(theme) {
            try {
                // 使用 window.postMessage 发送消息
                window.postMessage({
                    event_type: 'evaluate_on_completion',
                    message: '任务结束时Joplin的主题颜色是' + theme,
                    data: theme
                }, '*');
                console.log('Evaluation result sent successfully');
            } catch (error) {
                console.error('Error sending evaluation message:', error);
            }
        }
        
        // 监听主题变化
        joplin.settings.onChange(async (event) => {
            if (event.keys.includes('theme') || event.keys.includes('preferredLightTheme')) {
                const themeValue = await joplin.settings.globalValue('preferredLightTheme');
                const currentTheme = themeMap[themeValue] || 'Unknown';
                console.log('Current theme value:', themeValue, 'mapped to:', currentTheme);
                
                sendEvaluationMessage(currentTheme);
            }
        });

        // 初始检查当前主题
        const initialThemeValue = await joplin.settings.globalValue('preferredLightTheme');
        const initialTheme = themeMap[initialThemeValue] || 'Unknown';
        console.log('Initial theme value:', initialThemeValue, 'mapped to:', initialTheme);
        
        // 发送初始主题
        sendEvaluationMessage(initialTheme);
    }
}); 