# Evaluator 模块

这个模块用于评估Agent执行任务的效果，支持多种评估方式。

## 模块结构

```
evaluator/
├── __init__.py              # 模块初始化文件
├── base_evaluator.py        # 基础评估器类
├── ui_tree_evaluator.py     # 基于UI元素树的评估器
├── image_based_evaluator.py # 基于图像分析的评估器
├── tasks/                   # 任务定义目录
│   └── telegram_search_task.py  # Telegram搜索任务
├── logs/                    # 评估日志目录
└── references/              # 参考图像目录
```

## 使用方法

### 1. 创建任务

任务定义了一系列步骤和评估条件，例如：

```python
from evaluator.ui_tree_evaluator import UITreeEvaluator
from evaluator.image_based_evaluator import ImageBasedEvaluator

class MyTask:
    def __init__(self, use_ui_tree=True):
        self.task_name = "my_task"
        
        # 选择评估器类型
        if use_ui_tree:
            self.evaluator = UITreeEvaluator(self.task_name)
        else:
            self.evaluator = ImageBasedEvaluator(self.task_name)
            
        # 注册步骤
        self._register_steps()
        
    def _register_steps(self):
        # 注册步骤1
        self.evaluator.register_step(
            step_name="step1",
            description="第一步",
            check_func=self._check_step1,
            timeout=10
        )
        
        # 注册步骤2...
        
    def _check_step1(self, context):
        # 定义检查条件
        condition = {
            'type': 'window_exists',
            'title_pattern': 'My App'
        }
        return self.evaluator._check_condition(context, condition)
```

### 2. 运行评估

```python
# 创建任务
task = MyTask(use_ui_tree=False)  # Docker环境中使用图像评估

# 定义截图提供函数
def get_screenshot():
    return ImageGrab.grab()

# 运行评估
report = task.evaluator.evaluate_all(get_screenshot)
print(report)
```

### 3. 与Agent集成

```python
# 创建Agent和任务
agent = BaseAgent(model, observation_type="screenshot", action_space="pyautogui")
task = MyTask(use_ui_tree=False)

# 获取任务指令
instructions = task.get_instructions()

# 执行循环
while True:
    # 获取观察
    observation = get_screenshot()
    
    # 执行Agent决策
    action_code, thought = agent.act(instructions, observation, controller)
    
    # 评估当前步骤
    success = task.evaluator.evaluate_step(current_step, observation)
    
    # 根据评估结果决定下一步
    if success:
        # 进入下一步
        pass
```

## 评估器类型

### 1. UI树评估器 (UITreeEvaluator)

使用UI元素树进行评估，适用于可以访问UI层次结构的环境。

支持的条件类型：
- `window_exists`: 检查窗口是否存在
- `window_active`: 检查窗口是否活动
- `element_exists`: 检查元素是否存在
- `element_state`: 检查元素状态

### 2. 图像评估器 (ImageBasedEvaluator)

使用图像分析进行评估，适用于Docker等无法直接访问UI元素树的环境。

支持的条件类型：
- `reference_similarity`: 与参考图像比较相似度
- `region_brightness`: 检查区域亮度
- `region_change`: 检查区域变化
- `color_presence`: 检查颜色存在

## 扩展评估器

可以通过继承BaseEvaluator类来创建自定义评估器：

```python
from evaluator.base_evaluator import BaseEvaluator

class MyEvaluator(BaseEvaluator):
    def __init__(self, task_name):
        super().__init__(task_name)
        # 自定义初始化
        
    def _check_condition(self, context, condition):
        # 实现条件检查逻辑
        pass
        
    # 添加自定义方法
``` 