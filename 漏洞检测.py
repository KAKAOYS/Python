#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Auto Vulnerability Scanner for Kali Linux
# 警告：仅限合法授权测试使用！

import subprocess
import threading
import json
import time
from datetime import datetime

# ================= 配置区域 =================
TARGET_IP = "192.168.135.200"          # 目标IP/域名
OUTPUT_DIR = "scan_results"           # 结果保存目录
SCAN_INTENSITY = "T3"                 # nmap扫描强度（T1-T5），T3是一个较好的平衡
THREADS = 10                          # 并发线程数，适当增加线程数
# ============================================

class VulnerabilityScanner:
    def __init__(self):
        self.create_output_dir()
        self.report_data = {
            "start_time": datetime.now().isoformat(),
            "target": TARGET_IP,
            "findings": []
        }
        self.lock = threading.Lock()

    def create_output_dir(self):
        subprocess.run(f"mkdir -p {OUTPUT_DIR}", shell=True)

    def log_finding(self, tool, result):
        with self.lock:
            self.report_data["findings"].append({
                "tool": tool,
                "timestamp": datetime.now().isoformat(),
                "data": result
            })

    def run_command(self, command, tool_name):
        try:
            result = subprocess.check_output(
                command,
                shell=True,
                stderr=subprocess.STDOUT,
                text=True
            )
            self.log_finding(tool_name, result)
            self.save_raw_output(tool_name, result)
            return True
        except subprocess.CalledProcessError as e:
            self.log_finding(tool_name, f"ERROR: {e.output}")
            return False

    def save_raw_output(self, tool_name, data):
        filename = f"{OUTPUT_DIR}/{tool_name}_{datetime.now().strftime('%Y%m%d%H%M')}.txt"
        with open(filename, "w") as f:
            f.write(data)

    def generate_report(self):
        report_path = f"{OUTPUT_DIR}/final_report.json"
        with open(report_path, "w") as f:
            json.dump(self.report_data, f, indent=2)
        print(f"\n[+] 扫描报告已生成：{report_path}")

    def start_scan(self):
        # 阶段1：快速端口扫描
        if not self.run_command(
            f"nmap -sS -{SCAN_INTENSITY} -Pn -p- --open -oN {OUTPUT_DIR}/nmap_quick.txt {TARGET_IP}",
            "nmap_quick"
        ):
            print("[-] 初始端口扫描失败，终止流程")
            return

        # 阶段2：详细服务识别
        self.run_command(
            f"nmap -sV -sC -Pn -oN {OUTPUT_DIR}/nmap_service.txt {TARGET_IP}",
            "nmap_service"
        )

        # 阶段3：并发漏洞扫描
        scan_tasks = [
            {
                "cmd": f"nikto -h http://{TARGET_IP} -output {OUTPUT_DIR}/nikto_scan.txt",
                "name": "nikto"
            },
            {
                "cmd": f"dirb http://{TARGET_IP} /usr/share/dirb/wordlists/common.txt -o {OUTPUT_DIR}/dirb_scan.txt",
                "name": "dirb"
            },
            {
                "cmd": f"sslscan {TARGET_IP} > {OUTPUT_DIR}/sslscan.txt",
                "name": "sslscan"
            }
        ]

        # 移除sqlmap扫描，因为它通常需要较多时间且可能不适用于所有目标
        # {
        #     "cmd": f"sqlmap -u 'http://{TARGET_IP}/index.php?id=1' --batch --output-dir={OUTPUT_DIR}/sqlmap",
        #     "name": "sqlmap"
        # },

        threads = []
        for task in scan_tasks:
            t = threading.Thread(
                target=self.run_command,
                args=(task["cmd"], task["name"])
            )
            t.start()
            threads.append(t)
            if len(threads) >= THREADS:
                for t in threads:
                    t.join()
                threads = []

        for t in threads:
            t.join()

        # 生成最终报告
        self.generate_report()

if __name__ == "__main__":
    print("""\n
    ██████ 自动化漏洞扫描器 ██████
    版本: 1.0
    目标: {TARGET_IP}
    开始时间: {time}
    """.format(
        TARGET_IP=TARGET_IP,
        time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    
    scanner = VulnerabilityScanner()
    try:
        scanner.start_scan()
    except KeyboardInterrupt:
        print("\n[!] 用户中断扫描，正在生成当前报告...")
        scanner.generate_report()
