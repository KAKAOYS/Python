#!/usr/bin/env python3
import subprocess
import time
import datetime

# 检查hping3是否已安装
def check_hping3_installed():
    try:
        subprocess.run(["hping3", "--version"], check=True, stdout=subprocess.DEVNULL)
        print("hping3工具已安装。")
    except FileNotFoundError:
        print("hping3工具未安装，正在安装...")
        subprocess.run(["sudo", "apt", "install", "-y", "hping3"], check=True)
        print("hping3工具安装完成。")

# 执行hping3压力测试
def run_hping3_test(target_ip, duration, mode):
    print(f"开始hping3压力测试，目标IP：{target_ip}，持续时间：{duration}秒，模式：{mode}")
    start_time = datetime.datetime.now()
    print(f"测试开始时间：{start_time}")

    # 根据模式选择不同的hping3参数
    if mode == "syn":
        hping3_command = ["sudo", "hping3", "--flood", "--rand-source", "-S", "-p", "80", target_ip]
    elif mode == "icmp":
        hping3_command = ["sudo", "hping3", "--icmp", "--flood", "--rand-source", target_ip]
    elif mode == "udp":
        hping3_command = ["sudo", "hping3", "--udp", "--flood", "--rand-source", "-p", "53", target_ip]
    else:
        print("未知的测试模式，请选择 'syn', 'icmp' 或 'udp'。")
        return None, None

    # 启动hping3进程
    hping3_process = subprocess.Popen(
        hping3_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    # 等待测试完成
    time.sleep(duration)
    hping3_process.terminate()
    hping3_process.wait()

    end_time = datetime.datetime.now()
    print(f"测试结束时间：{end_time}")
    return start_time, end_time

# 保存测试结果到日志文件
def save_test_results(start_time, end_time, log_file):
    with open(log_file, "a") as file:
        file.write(f"测试开始时间：{start_time}\n")
        file.write(f"测试结束时间：{end_time}\n")
        file.write(f"测试持续时间：{end_time - start_time}\n")
        file.write("-" * 50 + "\n")

# 主函数
def main():
    check_hping3_installed()

    # 用户输入目标IP地址
    target_ip = input("请输入目标IP地址：")
    # 用户输入测试持续时间
    duration = int(input("请输入测试持续时间（秒）："))
    # 用户输入测试模式
    mode = input("请输入测试模式（syn/icmp/udp）：").lower()

    start_time, end_time = run_hping3_test(target_ip, duration, mode)
    if start_time and end_time:
        save_test_results(start_time, end_time, "hping3_test_log.txt")
        print(f"测试结果已保存到 hping3_test_log.txt")

if __name__ == "__main__":
    main()
