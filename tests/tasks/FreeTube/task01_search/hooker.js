// renderer.js
const { ipcRenderer } = require('electron');

function waitForElement(selector) {
  return new Promise((resolve) => {
    const element = document.querySelector(selector);
    if (element) resolve(element);
    else {
      const observer = new MutationObserver(() => {
        const el = document.querySelector(selector);
        if (el) {
          observer.disconnect();
          resolve(el);
        }
      });
      observer.observe(document.body, { childList: true, subtree: true });
    }
  });
}

let originalHandleClick = null;
let customListener = null;

function modifyHandleClick(vueInstance) {
  if (vueInstance && vueInstance.handleClick && !vueInstance.__handleClickModified) {
    originalHandleClick = vueInstance.handleClick;
    vueInstance.handleClick = function(event) {
      // 执行原始逻辑
      originalHandleClick.call(this, event);
      
      // 检查 inputData 是否为 'porsche'
      if (this.inputData === 'porsche') {
        console.log('handleClick: inputData is porsche');
        ipcRenderer.send('send', {
          'event_type': 'success',
          'message': '以keyDown或者点击条目的方式搜索了porsche, 任务成功',
        });
      } else {
        console.log('handleClick: inputData is not porsche:', this.inputData);
        ipcRenderer.send('send', {
          'event_type': 'keyDown_or_hit_option',
          'message': '以keyDown或者点击条目的方式进行了搜索, 但不是porsche',
        });
      }
    };
    vueInstance.__handleClickModified = true;
    console.log('handleClick modified');
    ipcRenderer.send('send', {
      'event_type': 'hook_keyDown_and_hit_option',
      'message': '成功hook handleClick函数'
    });
  } else {
    console.warn('Cannot modify handleClick: instance or method not found');
    ipcRenderer.send('send', {
      'event_type': 'error',
      'message': '无法hook handleClick函数',
    });
  }
}

function modifyDomListener(actionIcon) {
  if (actionIcon && !actionIcon.dataset.hasCustomListener) {
    customListener = (event) => {
      // 获取 Vue 实例以访问 inputData
      const vueInstance = document.querySelector('.ft-input-component').__vue__;
      if (vueInstance && vueInstance.inputData) {
        if (vueInstance.inputData === 'porsche') {
          console.log('DOM listener: inputData is porsche');
          ipcRenderer.send('send', {
            'event_type': 'success',
            'message': '点击了搜索button, 并且inputData是porsche, 任务成功',
          });
        } else {
          console.log('DOM listener: inputData is not porsche:', vueInstance.inputData);
          ipcRenderer.send('send', {
            'event_type': 'click_search_button',
            'message': '点击了搜索button, 但是inputData不是porsche',
          });
        }
      } else {
        console.warn('Vue instance or inputData not found');
      }
      console.log('Additional DOM logic executed!');
    };
    actionIcon.addEventListener('click', customListener);
    actionIcon.dataset.hasCustomListener = 'true';
    ipcRenderer.send('send', {
      'event_type': 'hook_search_button',
      'message': '成功hook搜索button',
    });
  } else {
    console.warn('Cannot add DOM listener: element not found or already modified');
    ipcRenderer.send('send', {
      'event_type': 'error',
      'message': '无法hook搜索button',
    });
  }
}

function restoreAll() {
  return Promise.all([
    // 恢复 handleClick
    waitForElement('.ft-input-component').then((element) => {
      const vueInstance = element.__vue__;
      if (vueInstance && vueInstance.__handleClickModified && originalHandleClick) {
        vueInstance.handleClick = originalHandleClick;
        delete vueInstance.__handleClickModified;
        console.log('handleClick restored');
      } else {
        console.log('No handleClick modification to restore');
      }
    }),
    // 移除 DOM 监听器
    waitForElement('.inputWrapper .inputAction').then((actionIcon) => {
      if (actionIcon && actionIcon.dataset.hasCustomListener && customListener) {
        actionIcon.removeEventListener('click', customListener);
        delete actionIcon.dataset.hasCustomListener;
        customListener = null;
        console.log('DOM listener removed');
      } else {
        console.log('No DOM listener to remove');
      }
    })
  ]).then(() => {
    originalHandleClick = null;
    console.log('All modifications restored');
  }).catch((err) => {
    console.error('Error during restoration:', err);
  });
}

// 应用修改
waitForElement('.ft-input-component').then((element) => {
  const vueInstance = element.__vue__;
  modifyHandleClick(vueInstance);
});
waitForElement('.inputWrapper .inputAction').then((actionIcon) => {
  modifyDomListener(actionIcon);
});

// 持续监听组件变化
const observer = new MutationObserver(() => {
  waitForElement('.ft-input-component').then((element) => {
    const vueInstance = element.__vue__;
    if (vueInstance && !vueInstance.__handleClickModified) {
      console.log('New component instance detected, no auto-modification');
    }
  });
});
observer.observe(document.body, { childList: true, subtree: true });

// 通过 IPC 触发撤销
ipcRenderer.on('restore', () => {
  restoreAll();
});