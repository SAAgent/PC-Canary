#!/usr/bin/env python3
import subprocess
import sys
import time
import threading
import signal
import atexit
import os

# 全局变量存储进程信息
processes = []

def run_command(command, description):
    """在独立线程中运行命令"""
    print(f"开始 {description}...")
    try:
        # 使用 Popen 而不是 run，并创建新的进程组
        process = subprocess.Popen(
            command,
            shell=True,
            preexec_fn=os.setsid  # 在新的进程组中启动
        )
        
        # 保存进程信息
        processes.append({
            'process': process,
            'description': description,
            'pgid': os.getpgid(process.pid)  # 进程组 ID
        })
        
        # 等待进程完成
        process.wait()
        print(f"{description} 完成")
        return True
    except subprocess.CalledProcessError as e:
        print(f"{description} 失败: {e}")
        return False
    except Exception as e:
        print(f"{description} 异常: {e}")
        return False

def cleanup_all():
    """清理所有子进程及其子进程"""
    print("\n正在清理所有进程...")
    for proc_info in processes:
        try:
            pgid = proc_info['pgid']
            description = proc_info['description']
            
            print(f"正在终止 {description}...")
            
            # 终止整个进程组
            try:
                os.killpg(pgid, signal.SIGTERM)
                time.sleep(2)  # 给进程时间优雅关闭
                
                # 检查进程是否还在运行
                if proc_info['process'].poll() is None:
                    print(f"强制终止 {description}...")
                    os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                print(f"{description} 已经退出")
            except Exception as e:
                print(f"终止 {description} 时出错: {e}")
                
        except Exception as e:
            print(f"清理进程时出错: {e}")

def signal_handler(signum, frame):
    """处理信号"""
    print(f"\n收到信号 {signum}，正在清理...")
    cleanup_all()
    sys.exit(0)

# 注册清理函数和信号处理器
atexit.register(cleanup_all)
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# 设置命令
command1 = "python /home/agent/agent-demo/PC-Canary/tests/tasks/zotero/tools/socketio_proxy.py"
command2 = "/home/agent/agent_test/esbuild.js /home/agent/agent_test/main.js hookAddItemTag"

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
cleanup_all()  # 确保清理