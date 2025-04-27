const { ipcRenderer } = require('electron');

// Function to modify the createNewPlaylist logic
function modifyCreatePlaylistLogic() {
  // Find the ft-input with class playlistNameInput
  const inputComponent = document.querySelector('.playlistNameInput');

  // Find the ft-button with the specific label
  const createButton = Array.from(document.querySelectorAll('button')).find(button => {
    return button.textContent.trim() === 'Create'; // Adjust for localized text
  });
  // Proceed only if both components are found
  if (!inputComponent || !createButton) {
    ipcRenderer.send('send', {
      'event_type': 'failed_to_find_vue',
      'message': '无法找到vue组件',
    });
    console.log('Components not found:', { inputComponent, createButton });
    return;
  }
  
  if (createButton) {
    createButton.addEventListener('click', (event) => {
      console.log('Create Playlist button clicked!', event);
      // Add your custom logic here
      ipcRenderer.send('send', {
        'event_type': 'click_button',
        'message': '点击create按钮',
      });
    });
    ipcRenderer.send('send', {
      'event_type': 'hook_click_button',
      'message': '成功添加button点击事件',
    });
  } else {
    console.warn('Create button not found');
    ipcRenderer.send('send', {
      'event_type': 'hook_click_button_failed',
      'message': '添加button点击事件失败',
    });
  }

  console.log('Target components found! Attempting to modify logic...');

  // Try to find the Vue component ancestor
  let vueComponentElement = inputComponent;
  let vueInstance = null;

  // Traverse up the DOM to find a Vue component
  while (vueComponentElement && vueComponentElement !== document.body) {
    if (vueComponentElement.__vueParentComponent) {
      vueInstance = vueComponentElement.__vueParentComponent;
      break;
    }
    if (vueComponentElement.__vue__) {
      vueInstance = vueComponentElement.__vue__;
      break;
    }
    vueComponentElement = vueComponentElement.parentElement;
  }

  if (vueInstance) {
    console.log('Vue instance found:', vueInstance);

    // Access the component's context (Vue 3: ctx, Vue 2: direct)
    const context = vueInstance.ctx || vueInstance;

    // Check $el.__vue__ for handleClick and handleInput
    const elVueInstance = context.$el && context.$el.__vue__;
    if (elVueInstance) {
      console.log('Found $el.__vue__:', elVueInstance);
      console.log('Available methods:', Object.keys(elVueInstance));

      // Check if handleClick exists
      if (typeof elVueInstance.handleClick === 'function') {
        console.log('Modifying handleClick...');

        // Store the original handleClick
        const originalHandleClick = elVueInstance.handleClick;

        // Override handleClick
        elVueInstance.handleClick = function (...args) {
          console.log('Custom handleClick logic triggered!');
          ipcRenderer.send('send', {
            'event_type': 'input_enter',
            'message': '通过回车创建playlist',
          });
          console.log(this.inputData);
          originalHandleClick.apply(this, args);
        };
        console.log('handleClick successfully modified.');
        ipcRenderer.send('send', {
          'event_type': 'hook_input_enter',
          'message': '成功添加搜索框回车事件',
        });
      } else {
        console.warn('handleClick not found in $el.__vue__.');
        ipcRenderer.send('send', {
          'event_type': 'hook_input_enter_failed',
          'message': '添加搜索框回车事件失败',
        });
      }

      // Check if handleInput exists
      if (typeof elVueInstance.handleInput === 'function') {
        console.log('Modifying handleInput...');

        // Store the original handleInput
        const originalHandleInput = elVueInstance.handleInput;

        // Override handleInput
        elVueInstance.handleInput = function (...args) {
          originalHandleInput.apply(this, args);
          console.log('Custom handleInput logic triggered!');
          ipcRenderer.send('send', {
            'event_type': 'inputdata_change',
            'message': '输入框内容变化为:'+this.inputData,
            'data': this.inputData,
          });
          console.log(this.inputData);
        };
        ipcRenderer.send('send', {
          'event_type': 'hook_input',
          'message': '添加搜索框输入事件',
        });
        console.log('handleInput successfully modified.');
      } else {
        console.warn('handleInput not found in $el.__vue__.');
        ipcRenderer.send('send', {
          'event_type': 'hook_input_failed',
          'message': '添加搜索框输入事件失败',
        });
      }
    } else {
      ipcRenderer.send('send', {
        'event_type': 'hook_inputbox_failed',
        'message': '添加搜索框输入事件失败',
      });
      console.warn('$el.__vue__ not found. Falling back to event listener.');
    }
  } else {
    console.error('Could not find Vue instance.');
  }
}

// Set up MutationObserver to detect DOM changes
const observer = new MutationObserver((mutations) => {
  mutations.forEach(() => {
    modifyCreatePlaylistLogic();
  });
});

// Start observing the document body
observer.observe(document.body, {
  childList: true,
  subtree: true,
});

// Initial check
modifyCreatePlaylistLogic();