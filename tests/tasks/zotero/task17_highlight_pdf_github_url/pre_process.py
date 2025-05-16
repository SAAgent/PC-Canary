#!/usr/bin/env python3
import subprocess
import sys
import time
import threading

def run_command(command, description):
    """在独立线程中运行命令"""
    print(f"开始 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True)
        print(f"{description} 完成")
        return True
    except subprocess.CalledProcessError as e:
        print(f"{description} 失败: {e}")
        return False
    except Exception as e:
        print(f"{description} 异常: {e}")
        return False

# 设置命令
command1 = "python /home/agent/agent-demo/PC-Canary/tests/tasks/zotero/tools/socketio_proxy.py"
command2 = "/home/agent/agent_test/esbuild.js hookGenerateNote hookAddCollection"

# 创建线程来执行命令
thread1 = threading.Thread(target=run_command, args=(command1, "SocketIO 代理"))
thread2 = threading.Thread(target=run_command, args=(command2, "esbuild"))

# 启动线程
thread1.start()
time.sleep(1)  # 给 socketio_proxy 一点启动时间
thread2.start()

# 等待两个线程完成
thread1.join()
thread2.join()

print("\n所有命令执行完毕")