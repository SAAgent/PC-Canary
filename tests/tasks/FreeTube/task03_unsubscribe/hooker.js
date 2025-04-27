(function() {
    // 使用 WeakSet 跟踪已注入的按钮
    const injectedButtons = new WeakSet();
    // 保存注入的按钮元素引用，便于恢复
    const injectedButtonElements = [];
    // 保存 MutationObserver 实例
    let observerInstance = null;
    // 标志：是否已强制取消 Porsche 订阅
    let hasUnsubscribedPorsche = false;
  
    // 获取 ipcRenderer
    let ipcRenderer;
    try {
      ipcRenderer = window.require('electron').ipcRenderer;
      console.log('ipcRenderer loaded via require');
    } catch (e) {
      console.warn('Failed to load ipcRenderer via require, relying on electronAPI:', e);
    }
  
    // 检查并强制取消 Porsche 订阅
    const checkAndUnsubscribePorsche = (subscribeButton) => {
      if (hasUnsubscribedPorsche) {
        console.log('Porsche unsubscribe already performed, skipping');
        return false;
      }
  
      const vm = subscribeButton.__vue__ || subscribeButton.__vue_app__?._component;
      if (!vm) {
        console.error('Vue component not found for button:', subscribeButton);
        return false;
      }
  
      let channelName = vm._props?.channelName || vm._ctx?.props?.channelName || vm.props?.channelName;
      const mainButton = subscribeButton.querySelector('.subscribeButton');
      if (!channelName && mainButton) {
        const buttonText = mainButton.textContent.toLowerCase();
        channelName = buttonText.includes('porsche') ? 'Porsche' : 'Unknown';
      }
  
      if (channelName !== 'Porsche') {
        console.log('Not Porsche channel, skipping unsubscribe check');
        return false;
      }
  
      let isSubscribed = false;
      try {
        isSubscribed = vm.isProfileSubscribed?.(vm.activeProfile) || false;
      } catch (e) {
        console.warn('Failed to check isProfileSubscribed for Porsche:', e);
      }
  
      if (!isSubscribed && !vm.isProfileSubscribed && mainButton) {
        const buttonText = mainButton.textContent.toUpperCase();
        isSubscribed = buttonText.includes(vm._ctx?.t?.('Channel.Unsubscribe')?.toUpperCase() || 'UNSUBSCRIBE');
      }
  
      console.log('Porsche channel isSubscribed:', isSubscribed, 'for button:', subscribeButton);
  
      if (!isSubscribed && mainButton) {
        console.log('Porsche is subscribed, forcing subscribe');
        // 临时禁用注入的 onclick
        const originalOnclick = mainButton.onclick;
        mainButton.onclick = null;
  
        // 触发原始 click 事件
        const clickEvent = new Event('click', { bubbles: true, cancelable: true });
        mainButton.dispatchEvent(clickEvent);
  
        // 延迟刷新页面
        // setTimeout(() => {
        //   console.log('Reloading page to ensure Porsche is unsubscribed');
        //   window.location.reload();
        // }, 500);
  
        // 标记已取消订阅
        hasUnsubscribedPorsche = true;
        return true; // 表示已处理
      } else {
        console.log('Porsche is already subscribed, proceeding with injection');
        hasUnsubscribedPorsche = true;
        return false;
      }
    };
  
    // 定义 MutationObserver 回调
    const observeDOM = () => {
      observerInstance = new MutationObserver((mutations, obs) => {
        const subscribeButtons = document.querySelectorAll('.ftSubscribeButton');
        subscribeButtons.forEach((subscribeButton) => {
          if (!injectedButtons.has(subscribeButton)) {
            // 检查 Porsche 状态
            const handled = checkAndUnsubscribePorsche(subscribeButton);
            if (!handled) {
              // 未触发刷新，继续注入
              injectSubscriptionLogic(subscribeButton);
              injectedButtons.add(subscribeButton);
              injectedButtonElements.push(subscribeButton);
            }
          }
        });
      });
  
      observerInstance.observe(document.body, {
        childList: true,
        subtree: true
      });
      console.log('MutationObserver started');
    };
  
    // 注入逻辑的函数
    const injectSubscriptionLogic = (subscribeButton) => {
      const vm = subscribeButton.__vue__ || subscribeButton.__vue_app__?._component;
      if (!vm) {
        ipcRenderer.send('send', {
          'event_type': 'error',
          'message': '无法找到关注按钮',
        });
        console.error('Vue component not found for button:', subscribeButton);
        return;
      }
  
      console.log('VM structure for button:', subscribeButton, vm);
  
      const mainButton = subscribeButton.querySelector('.subscribeButton');
      const profileItems = subscribeButton.querySelectorAll('.profileList .profile');
  
      if (mainButton) {
        mainButton.onclick = function(event) {
          let channelName = vm._props?.channelName || vm._ctx?.props?.channelName || vm.props?.channelName;
          let isSubscribed = false;
          try {
            isSubscribed = vm.isProfileSubscribed?.(vm.activeProfile) || false;
          } catch (e) {
            console.warn('Failed to check isProfileSubscribed:', e);
          }
  
          if (!isSubscribed && !vm.isProfileSubscribed) {
            const buttonText = mainButton.textContent.toUpperCase();
            isSubscribed = buttonText.includes(vm._ctx?.t?.('Channel.Unsubscribe')?.toUpperCase() || 'UNSUBSCRIBE');
          }
  
          if (!channelName) {
            const buttonText = mainButton.textContent.toLowerCase();
            channelName = buttonText.includes('porsche') ? 'Porsche' : 'Unknown';
            console.warn('Fallback to DOM inference for channelName:', channelName, 'for button:', subscribeButton);
          }
  
          console.log('channelName:', channelName, 'isSubscribed:', isSubscribed, 'for mainButton:', subscribeButton);
  
          if (isSubscribed) {
            console.log('Unsubscribing from Porsche');
            ipcRenderer.send('send', {
              'event_type': 'unsubscribing',
              'message': '取消对频道的关注',
              'channelName': channelName,
            });
          } else {
            console.log('Subscribing to Porsche');
            ipcRenderer.send('send', {
              'event_type': 'subscribing',
              'message': '关注频道',
              'channelName': channelName,
            });
          }
        };
      }
  
      profileItems.forEach((item, index) => {
        const profileName = item.querySelector('.profileName')?.textContent || `Profile_${index}`;
        item.onclick = function(event) {
          event.stopPropagation();
          event.preventDefault();
          let channelName = vm._props?.channelName || vm._ctx?.props?.channelName || vm.props?.channelName;
          let isSubscribed = false;
          try {
            const profile = { _id: profileName };
            isSubscribed = vm.isProfileSubscribed?.(profile) || false;
          } catch (e) {
            console.warn('Failed to check isProfileSubscribed for profile:', e);
          }
  
          if (!isSubscribed && !vm.isProfileSubscribed) {
            isSubscribed = item.classList.contains('subscribed') || item.textContent.includes(vm._ctx?.t?.('checkmark') || '✓');
          }
  
          if (!channelName) {
            const buttonText = mainButton?.textContent.toLowerCase();
            channelName = buttonText?.includes('porsche') ? 'Porsche' : 'Unknown';
            console.warn('Fallback to DOM inference for channelName:', channelName, 'for button:', subscribeButton);
          }
  
          console.log('channelName:', channelName, 'isSubscribed:', isSubscribed, 'for profileItem:', profileName, 'button:', subscribeButton);
  
          if (isSubscribed) {
            console.log('Unsubscribing from Porsche');
            ipcRenderer.send('send', {
              'event_type': 'unsubscribing',
              'message': '取消对频道的关注',
              'channelName': channelName,
            });
          } else {
            console.log('Subscribing to Porsche');
            ipcRenderer.send('send', {
              'event_type': 'subscribing',
              'message': '关注频道',
              'channelName': channelName,
            });
          }
  
          const clickEvent = new Event('click', { bubbles: true, cancelable: true });
          item.dispatchEvent(clickEvent);
        };
  
        item.onkeydown = function(event) {
          if (event.code === 'Space') {
            event.stopPropagation();
            event.preventDefault();
            let channelName = vm._props?.channelName || vm._ctx?.props?.channelName || vm.props?.channelName;
            let isSubscribed = false;
            try {
              const profile = { _id: profileName };
              isSubscribed = vm.isProfileSubscribed?.(profile) || false;
            } catch (e) {
              console.warn('Failed to check isProfileSubscribed for profile:', e);
            }
  
            if (!isSubscribed && !vm.isProfileSubscribed) {
              isSubscribed = item.classList.contains('subscribed') || item.textContent.includes(vm._ctx?.t?.('checkmark') || '✓');
            }
  
            if (!channelName) {
              const buttonText = mainButton?.textContent.toLowerCase();
              channelName = buttonText?.includes('porsche') ? 'Porsche' : 'Unknown';
              console.warn('Fallback to DOM inference for channelName:', channelName, 'for button:', subscribeButton);
            }
  
            console.log('channelName:', channelName, 'isSubscribed:', isSubscribed, 'for profileItem keydown:', profileName, 'button:', subscribeButton);
  
            if (isSubscribed) {
              console.log('Unsubscribing from Porsche');
              ipcRenderer.send('send', {
                'event_type': 'unsubscribing',
                'message': '取消对频道的关注',
                'channelName': channelName,
              });
            } else {
              console.log('Subscribing to Porsche');
              ipcRenderer.send('send', {
                'event_type': 'subscribing',
                'message': '关注频道',
                'channelName': channelName,
              });
            }
  
            const keydownEvent = new KeyboardEvent('keydown', { code: 'Space', bubbles: true, cancelable: true });
            item.dispatchEvent(keydownEvent);
          }
        };
      });
  
      console.log('Subscription logic injected for button:', subscribeButton);
      ipcRenderer.send('send', {
        'event_type': 'hook_success',
        'message': '成功hook',
      });
    };
  
    // 恢复所有组件状态的接口
    window.restoreAll = function() {
      if (observerInstance) {
        observerInstance.disconnect();
        observerInstance = null;
        console.log('MutationObserver stopped');
      }
  
      injectedButtonElements.forEach((subscribeButton) => {
        const mainButton = subscribeButton.querySelector('.subscribeButton');
        const profileItems = subscribeButton.querySelectorAll('.profileList .profile');
  
        if (mainButton) {
          mainButton.onclick = null;
        }
  
        profileItems.forEach((item) => {
          item.onclick = null;
          item.onkeydown = null;
        });
  
        injectedButtons.delete(subscribeButton);
        console.log('Restored event listeners for button:', subscribeButton);
      });
  
      injectedButtonElements.length = 0;
      console.log('All components restored');
    };
  
    // 初始检查
    const initialCheck = () => {
      const subscribeButtons = document.querySelectorAll('.ftSubscribeButton');
      subscribeButtons.forEach((subscribeButton) => {
        if (!injectedButtons.has(subscribeButton)) {
          // 检查 Porsche 状态
          const handled = checkAndUnsubscribePorsche(subscribeButton);
          if (!handled) {
            // 未触发刷新，继续注入
            injectSubscriptionLogic(subscribeButton);
            injectedButtons.add(subscribeButton);
            injectedButtonElements.push(subscribeButton);
          }
        }
      });
    };
  
    // 执行初始检查
    initialCheck();
  
    // 开始观察 DOM 变化
    observeDOM();
  
    // 监听 IPC 恢复事件
    if (window.electronAPI && window.electronAPI.onRestore) {
      window.electronAPI.onRestore(() => {
        console.log('Received restore IPC event via electronAPI');
        window.restoreAll();
      });
    } else {
      console.warn('electronAPI.onRestore not available, trying direct ipcRenderer');
      if (ipcRenderer) {
        ipcRenderer.on('restore', () => {
          console.log('Received restore IPC event via ipcRenderer');
          window.restoreAll();
        });
      } else {
        console.error('No IPC mechanism available');
      }
    }
  })();