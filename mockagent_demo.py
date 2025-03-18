import os
import sys
import time
import argparse
import signal
import threading
from PIL import Image, ImageGrab

# 添加项目根目录到路径
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.append(PROJECT_ROOT)

from evaluator.core.base_evaluator import BaseEvaluator
from env.controller.code_execution_controller import CodeExecutionController

# 模拟代理类
class MockAgent:
    def __init__(self):
        self.commands = [
            "pyautogui.click(322,122)",
            "pyautogui.write('new')",
            "pyautogui.press('enter')"
        ]
        self.current_step = 0
        
    def act(self, instructions, observation, controller):
        """模拟代理决策过程"""
        # 检查是否还有命令可以执行
        if self.current_step < len(self.commands):
            action = self.commands[self.current_step]
            self.current_step += 1
            
            # 思考过程
            thought = f"步骤 {self.current_step}/{len(self.commands)}: 我将执行命令 '{action}'"
            
            # 如果是最后一个命令，标记任务完成
            if self.current_step == len(self.commands):
                thought += "\n任务即将完成，这是最后一个命令。"
                # 在动作后添加任务完成标记
                action = f"{action}\n\nDONE"
            
            return action, thought
        else:
            # 所有命令已执行完毕
            return "DONE", "所有命令已执行完毕，任务完成。"
    
    def _execute_action(self, action_code, controller):
        """执行动作"""
        result = None
        
        # 检查是否有特殊命令
        if action_code.strip() == "DONE":
            controller.task_completed = True
            result =  True, "任务标记为完成"
        elif action_code.strip() == "FAIL":
            controller.task_failed = True
            controller.failure_reason = "代理标记任务失败"
            result =  False, "任务标记为失败"
        else:
            # 去除可能的DONE/FAIL标记
            cleaned_code = action_code.split("\n\n")[0]
            result = controller.execute(cleaned_code)
            
            # 检查是否在代码中包含了DONE标记
            if "DONE" in action_code:
                controller.task_completed = True
                
        return result


def run_mock_agent_demo(app_path, log_dir="logs", timeout=300):
    """
    运行模拟代理演示
    
    Args:
        telegram_path: Telegram可执行文件路径
        log_dir: 日志目录
        timeout: 超时时间(秒)
    """
    # 创建日志目录
    os.makedirs(log_dir, exist_ok=True)
    
    # 任务信息
    task = {
        "category": "telegram",
        "id": "task01_search",
    }
    
    # 运行标志
    running_flag = {'running': True}
    
    # 初始化评估器
    evaluator = BaseEvaluator(task, log_dir, app_path)
    evaluator.start()

    
    # 创建控制器
    controller = CodeExecutionController()
    
    # 创建模拟代理
    agent = MockAgent()
    
    # 任务指令
    instructions = """
    任务：在Telegram应用中执行搜索操作
    
    步骤：
    1. 启动Telegram应用程序（如果已打开，请确保它在前台）
    2. 点击搜索按钮（通常位于应用程序顶部）
    3. 在搜索框中输入"news"
    4. 等待搜索结果显示
    """
    
    print("\n" + "="*60)
    print("模拟代理演示 - Telegram搜索")
    print("="*60)
    print("任务: 在Telegram中搜索'news'")
    print("模式: 每次执行一行命令，验证多轮对话能力")
    print("命令列表:")
    for i, cmd in enumerate(agent.commands, 1):
        print(f"  {i}. {cmd}")
    print("="*60 + "\n")
    
    # 设置超时
    start_time = time.time()
    
    # 检查任务完成的线程函数
    def check_completion():
        while running_flag['running']:
            # 检查评估器是否正在运行
            if evaluator and not evaluator.is_running:
                print("\n检测到评估器已停止")
                running_flag['running'] = False
                break
                
            # 检查评估器指标
            if evaluator and hasattr(evaluator, 'metrics') and evaluator.metrics.get('success') is True:
                print("\n检测到评估器指标显示任务成功完成")
                running_flag['running'] = False
                break
                
            # 检查控制器状态
            if controller.task_completed:
                print("\n检测到控制器标记任务已完成")
                running_flag['running'] = False
                break
                
            # 检查是否超时
            if time.time() - start_time > timeout:
                print(f"\n演示超时 ({timeout}秒)")
                running_flag['running'] = False
                break
                
            time.sleep(0.5)
    
    # 启动检查线程
    completion_thread = threading.Thread(target=check_completion)
    completion_thread.daemon = True
    completion_thread.start()
    
    # 信号处理函数
    def signal_handler(sig, frame):
        print("\n\n用户中断演示...")
        running_flag['running'] = False
        if evaluator and evaluator.is_running:
            print("正在停止评估器...")
            evaluator.stop()
        sys.exit(0)
        
    # 设置信号处理
    signal.signal(signal.SIGINT, signal_handler)
    
    # 主循环
    step = 0
    try:
        while running_flag['running'] and step < len(agent.commands):
            print(f"\n执行步骤 {step+1}/{len(agent.commands)}")
            
            # 获取截图
            print("获取屏幕截图...")
            observation = controller.get_screenshot()
            
            # 保存截图
            screenshot_path = os.path.join(evaluator.session_dir, f"step_{step+1}_screenshot.png")
            if observation:
                observation.save(screenshot_path)
                print(f"截图已保存: {screenshot_path}")
            
            # 执行代理决策
            print("代理开始决策...")
            action_code, thought = agent.act(instructions, observation, controller)
            
            # 打印代理思考和动作
            print(f"\n代理思考:")
            print("-" * 50)
            print(thought)
            print("-" * 50)
            
            print(f"\n代理动作:")
            print("-" * 50)
            print(action_code)
            print("-" * 50)
            # 等待用户确认 (模拟多轮对话)
            try:
                input("按Enter键继续...")
            except Exception:
                # 如果出现异常，使用简单的等待
                time.sleep(10)
            # 执行代码
            execution_result = agent._execute_action(action_code, controller)
            
            print(f"代码执行结果: {'成功' if execution_result[0] else '失败'}")
            # 增加步骤计数
            step += 1

            

            if evaluator.task_completed:
                print("\nevaluator报告任务已完成")
                input("按Enter键结束任务\n")
                evaluator.stop()
                print("\nevaluator已经终止运行")
                break

            # 检查超时
            if time.time() - start_time > timeout:
                print(f"\n演示超时 ({timeout}秒)")
                break
        
        # 等待评估器完成
        if evaluator and evaluator.is_running:
            print("\n等待评估器完成...")
            # 最多等待5秒
            wait_start = time.time()
            while evaluator.is_running and time.time() - wait_start < 5:
                time.sleep(0.5)
                
            # 如果仍在运行，停止它
            if evaluator.is_running:
                print("手动停止评估器...")
                evaluator.stop()
            
        # 生成报告
        print("\n" + "="*60)
        print("模拟代理演示报告")
        print("="*60)
        print(f"执行步骤: {step}/{len(agent.commands)}")
        print(f"执行时间: {time.time() - start_time:.2f} 秒")
        print(f"任务状态: {'任务完成' if evaluator.task_completed else '任务未完成'}")
        
        # 打印评估器结果 (如果有)
        if evaluator:
            if hasattr(evaluator, 'get_results') and callable(getattr(evaluator, 'get_results')):
                results = evaluator.get_results()
                print("\n评估结果:")
                print(results)
            elif hasattr(evaluator, 'metrics'):
                print("\n评估指标:")
                print(evaluator.metrics)
            
            # 打印结果文件位置
            if hasattr(evaluator, 'result_file') and evaluator.result_file:
                print(f"\n结果文件: {evaluator.result_file}")
        
    except Exception as e:
        print(f"\n演示过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # 确保评估器被停止
        if evaluator and evaluator.is_running:
            evaluator.stop()
        
        print("\n演示结束")
    
    return evaluator.task_completed or controller.task_completed


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="模拟代理演示 - Telegram搜索")
    parser.add_argument("--telegram-path", type=str, default="apps/tdesktop/out/Debug/Telegram",
                       help="Telegram可执行文件路径")
    parser.add_argument("--log-dir", type=str, default="logs",
                       help="日志目录 (默认: logs)")
    parser.add_argument("--timeout", type=int, default=300,
                       help="超时时间，秒 (默认: 300)")
    
    args = parser.parse_args()
    
    # 检查Telegram路径
    if not os.path.exists(args.telegram_path):
        print(f"错误: Telegram可执行文件不存在: {args.telegram_path}")
        return 1
    
    try:
        # 运行演示
        success = run_mock_agent_demo(
            app_path=args.telegram_path,
            log_dir=args.log_dir,
            timeout=args.timeout
        )
        
        print(f"\n演示{'成功' if success else '失败'}")
        return 0 if success else 1
        
    except KeyboardInterrupt:
        print("\n用户中断，退出程序")
        return 130
    except Exception as e:
        print(f"\n执行出错: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main()) 