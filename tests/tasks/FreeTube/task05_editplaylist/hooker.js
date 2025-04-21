// 1. 监控edit playlist info按钮, 判断修改对象是否正确
// 2. 监控两个输入框: 发送输入内容, 监控enter事件
// 3. 监控save changes按钮

const { ipcRenderer } = require('electron');

// 创建 MutationObserver 实例
const observer = new MutationObserver((mutationsList) => {
    for (const mutation of mutationsList) {
        if (mutation.type === 'childList' || mutation.type === 'subtree') {
            const playlistTitleInput = document.querySelector('.inputElement');

            if (playlistTitleInput) {
                // console.log(playlistTitleInput.__vue__);
                // console.log(playlistTitleInput.__vue__.$el.__vue__);
                // console.log('Detected playlistTitleInput:', playlistTitleInput);

                let title_vueInstance = playlistTitleInput.__vue__;
                console.log(title_vueInstance.inputData);
                ipcRenderer.send('send', {
                    'event_type': 'find_name_inputbox',
                    'message': '检测到name输入框:'+title_vueInstance.inputData,
                    'data': title_vueInstance.inputData,
                });
                if (typeof title_vueInstance.handleClick === 'function') {
                    // Store the original handleClick
                    const originalHandleClick = title_vueInstance.handleClick;

                    // Override handleClick
                    title_vueInstance.handleClick = function (...args) {
                        console.log('Custom handleClick logic triggered!');
                        console.log(this.inputData);
                        originalHandleClick.apply(this, args);
                        ipcRenderer.send('send', {
                            'event_type': 'save_edit_by_enter',
                            'message': '通过回车触发保存',
                        });
                    };
                    console.log('handleClick successfully modified.');
                    ipcRenderer.send('send', {
                        'event_type': 'hook_name_inputbox_click',
                        'message': '成功hook到name输入框的click事件',
                    });
                }
                if (typeof title_vueInstance.handleInput === 'function') {
                    // Store the original handleInput
                    const originalHandleInput = title_vueInstance.handleInput;

                    // Override handleInput
                    title_vueInstance.handleInput = function (...args) {
                        originalHandleInput.apply(this, args);
                        console.log('Custom handleInput logic triggered!');
                        console.log(this.inputData);
                        ipcRenderer.send('send', {
                            'event_type': 'edit_name',
                            'message': '修改playlist的名字为:'+this.inputData,
                            'data': this.inputData,
                        });
                    };
                    console.log('handleInput successfully modified.');
                    ipcRenderer.send('send', {
                        'event_type': 'hook_name_inputbox_input',
                        'message': '成功hook到name输入框的input事件',
                    });
                }
            }


            const descriptionInput = document.querySelector('.inputElement.descriptionInput');

            if (descriptionInput) {
                //   console.log(descriptionInput.__vue__);
                //   console.log(descriptionInput.__vue__.$el.__vue__);
                let des_vueInstance = descriptionInput.__vue__;
                // console.log(des_vueInstance.inputData);
                ipcRenderer.send('send', {
                    'event_type': 'find_description_inputbox',
                    'message': '检测到description输入框:'+des_vueInstance.inputData,
                    'data': des_vueInstance.inputData,
                });
                if (typeof des_vueInstance.handleClick === 'function') {
                    // Store the original handleClick
                    const originalHandleClick = des_vueInstance.handleClick;

                    // Override handleClick
                    des_vueInstance.handleClick = function (...args) {
                        console.log('Custom handleClick logic triggered!');
                        console.log(this.inputData);
                        originalHandleClick.apply(this, args);
                        ipcRenderer.send('send', {
                            'event_type': 'save_edit_by_enter',
                            'message': '通过回车触发保存',
                        });
                    };
                    console.log('handleClick successfully modified.');
                    ipcRenderer.send('send', {
                        'event_type': 'hook_description_inputbox_click',
                        'message': '成功hook到description输入框的click事件',
                    });
                }
                if (typeof des_vueInstance.handleInput === 'function') {
                    // Store the original handleInput
                    const originalHandleInput = des_vueInstance.handleInput;

                    // Override handleInput
                    des_vueInstance.handleInput = function (...args) {
                        originalHandleInput.apply(this, args);
                        console.log('Custom handleInput logic triggered!');
                        console.log(this.inputData);
                        ipcRenderer.send('send', {
                            'event_type': 'edit_description',
                            'message': '修改playlist的简介:'+this.inputData,
                            'data': this.inputData,
                        });
                    };
                    console.log('handleInput successfully modified.');
                    ipcRenderer.send('send', {
                        'event_type': 'hook_description_inputbox_input',
                        'message': '成功hook到description输入框的input事件',
                    });
                }
            }

            const saveButton = Array.from(document.querySelectorAll('.ftIconButton')).find(button => {
                return button.textContent.trim() === 'Save Changes';
            });
            if (saveButton) {
                saveButton.addEventListener('click', (event) => {
                    console.log('Create Playlist button clicked!', event);
                    // Add your custom logic here
                    ipcRenderer.send('send', {
                        'event_type': 'save_by_click_button',
                        'message': '通过点击保存按钮触发保存',
                    });
                });
            } else {
                console.warn('Create button not found');
            }

        }
    }
});

// 配置 MutationObserver，监控 DOM 树的变化
const config = {
    childList: true, // 监控子节点的添加或移除
    subtree: true,   // 监控所有后代节点
    attributes: false // 不需要监控属性变化
};

// 选择要观察的目标节点
const targetNode = document.body || document.documentElement;

// 开始观察
observer.observe(targetNode, config);