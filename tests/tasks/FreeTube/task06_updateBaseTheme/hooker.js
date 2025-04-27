console.log("dafadsfasd")
console.log('开始监控 FtSelect 组件并修改 updateBaseTheme...');
const { ipcRenderer } = require('electron');
// 使用 MutationObserver 确保动态加载的组件被检测到
const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
        if (mutation.addedNodes.length > 0) {
            mutation.addedNodes.forEach((node) => {
                if (node.nodeType === Node.ELEMENT_NODE) {
                    const baseThemeDiv = Array.from(node.querySelectorAll(".select"))[7];
                    if (baseThemeDiv) {
                        const baseThemeVue = baseThemeDiv.__vue__;
                        if (baseThemeVue.value !== "system") {
                            baseThemeVue.change("system");
                            console.log("evaluator change theme to system first");
                            ipcRenderer.send('send', {
                                'event_type': 'change_theme_on_load',
                                'message': '在加载页面时事先修改主题颜色',
                            });
                        }
                        const originChangeFunction = baseThemeVue.change;
                        baseThemeVue.change = function (...args) {
                            console.log("change theme from:"+this._props.value);
                            originChangeFunction.apply(this, args);
                            console.log("change theme to:"+args);
                            ipcRenderer.send('send', {
                                'event_type': 'change_theme_to',
                                'message': '修改主题颜色为'+args,
                                'data': args,
                            });
                        };
                        ipcRenderer.send('send', {
                            'event_type': 'hook_change',
                            'message': '成功修改change函数',
                        });
                    }
                }
            });
        }
    });
});

observer.observe(document.body, {
    childList: true,
    subtree: true,
});