#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP 段端口扫描工具（纯 Python 标准库，无需安装任何依赖）

功能：
    给定一个 IP 段（起始 IP ~ 结束 IP）和一个端口，逐台尝试 TCP 连接，
    自动识别哪些 IP 的该端口可以连通（开放）。

用法：
    1. 只需要改下面「配置区」里的 START_IP / END_IP / PORT 三行；
    2. 保存后手动运行：python3 ip_port_scanner.py
       （命令行参数可临时覆盖：python3 ip_port_scanner.py --start 10.0.0.1 --end 10.0.0.254 --port 81）

免责声明：
    本工具仅用于你本人拥有或已获得授权测试的网络。未经允许扫描他人网络/主机属于违法行为，责任自负。
"""

# ========================= 配置区：只改这三行 =========================
START_IP = "8.8.0.0"            # 起始 IP  <- 自己改成要扫描的起点
END_IP   = "8.8.255.255"        # 结束 IP  <- 自己改成要扫描的终点
PORT     = 81                   # 要测试的端口  <- 自己改

# ------------------------- 下面是可选调优参数 -------------------------
THREADS  = 100                  # 并发线程数：内网可 300~500，公网建议 100~200
TIMEOUT  = 2.0                  # 单个 IP 连接超时（秒），网络慢可调到 3~5
OUTPUT_FILE = "open_result.txt" # 结果保存文件；留空字符串 "" 表示不保存
# =====================================================================


import argparse
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


def ip_to_int(ip):
    """把 IPv4 字符串转成整数，便于按顺序遍历整个 IP 段"""
    parts = ip.strip().split(".")
    if len(parts) != 4:
        raise ValueError("IP 格式错误：%s（应形如 192.168.1.1）" % ip)
    value = 0
    for part in parts:
        if not part.isdigit():
            raise ValueError("IP 格式错误：%s" % ip)
        n = int(part)
        if not 0 <= n <= 255:
            raise ValueError("IP 格式错误：%s（每段取值 0-255）" % ip)
        value = value * 256 + n
    return value


def int_to_ip(value):
    """整数还原成 IPv4 字符串"""
    return "%d.%d.%d.%d" % (
        (value >> 24) & 255,
        (value >> 16) & 255,
        (value >> 8) & 255,
        value & 255,
    )


def iter_ips(start_int, end_int):
    """惰性按顺序生成 IP，超大 IP 段也不会占内存"""
    value = start_int
    while value <= end_int:
        yield int_to_ip(value)
        value += 1


def is_port_open(ip, port, timeout):
    """TCP 连接测试：能连上就认为端口开放"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(
        description="IP 段端口扫描：默认读取文件顶部配置区，命令行参数可临时覆盖")
    parser.add_argument("--start", default=START_IP, help="起始 IP（默认取文件顶部配置）")
    parser.add_argument("--end", default=END_IP, help="结束 IP（默认取文件顶部配置）")
    parser.add_argument("--port", type=int, default=PORT, help="端口号 1-65535（默认取文件顶部配置）")
    parser.add_argument("--threads", type=int, default=THREADS, help="并发线程数")
    parser.add_argument("--timeout", type=float, default=TIMEOUT, help="单个 IP 连接超时（秒）")
    parser.add_argument("--output", default=OUTPUT_FILE, help="结果保存文件，留空不保存")
    args = parser.parse_args()

    port = args.port
    if not 1 <= port <= 65535:
        print("错误：端口号必须在 1-65535 之间，当前为 %d" % port)
        return
    if args.threads < 1:
        print("错误：线程数至少为 1")
        return
    if args.timeout <= 0:
        print("错误：超时时间必须大于 0")
        return

    try:
        start_int = ip_to_int(args.start)
        end_int = ip_to_int(args.end)
    except ValueError as exc:
        print("错误：%s" % exc)
        return

    if start_int > end_int:
        start_int, end_int = end_int, start_int
    total = end_int - start_int + 1
    start_ip = int_to_ip(start_int)
    end_ip = int_to_ip(end_int)

    print("=" * 62)
    print("IP 段端口扫描工具")
    print("免责声明：仅可用于你已获得授权的网络，非法扫描责任自负")
    print("=" * 62)
    print("扫描范围 : %s ~ %s" % (start_ip, end_ip))
    print("扫描端口 : %d" % port)
    print("IP 总数  : %d 个" % total)
    print("并发/超时: %d 线程 / %.1f 秒" % (args.threads, args.timeout))
    if total > 2000000:
        print("提示：IP 数量较大，预计耗时较长，可随时按 Ctrl+C 中断，"
              "已扫描到的开放 IP 会自动保留。")
    print("-" * 62)
    print("开始扫描，按 Ctrl+C 可随时中断……")
    print()

    fp = None
    if args.output:
        try:
            fp = open(args.output, "w", encoding="utf-8")
            fp.write("IP 段端口扫描结果\n")
            fp.write("扫描时间: %s\n" % time.strftime("%Y-%m-%d %H:%M:%S"))
            fp.write("IP 范围 : %s ~ %s\n" % (start_ip, end_ip))
            fp.write("扫描端口: %d\n" % port)
            fp.write("开放列表:\n")
            fp.flush()
        except Exception as exc:
            print("提示：结果文件 %s 打开失败（%s），本次不保存结果。" % (args.output, exc))
            fp = None

    done = 0
    open_ips = []
    started = time.time()
    interrupted = False
    batch_size = max(args.threads * 50, 1000)

    def handle_batch(executor, batch):
        nonlocal done
        future_map = {executor.submit(is_port_open, ip, port, args.timeout): ip for ip in batch}
        for future in as_completed(future_map):
            ip = future_map[future]
            done += 1
            if future.result():
                open_ips.append(ip)
                print("\n[开放] %s:%d  （第 %d 个开放）" % (ip, port, len(open_ips)))
                if fp:
                    fp.write("%s:%d\n" % (ip, port))
                    fp.flush()
            if done % 200 == 0 or done == total:
                elapsed = time.time() - started
                sys.stdout.write("\r进度: %d/%d (%.1f%%) | 已发现开放 %d 个 | 用时 %.0f 秒   "
                                 % (done, total, done * 100.0 / total, len(open_ips), elapsed))
                sys.stdout.flush()

    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            batch = []
            for ip in iter_ips(start_int, end_int):
                batch.append(ip)
                if len(batch) >= batch_size:
                    handle_batch(executor, batch)
                    batch = []
            if batch:
                handle_batch(executor, batch)
    except KeyboardInterrupt:
        interrupted = True
        print("\n\n用户中断扫描，保留已完成的部分结果。")

    duration = time.time() - started
    print()
    print("=" * 62)
    print("扫描结束（%s）" % ("已中断" if interrupted else "已完成"))
    print("已扫描: %d/%d 个    端口 %d 开放的主机: %d 个    总耗时: %.2f 秒"
          % (done, total, port, len(open_ips), duration))
    print("=" * 62)

    if open_ips:
        print("开放 %d 端口的 IP 列表：" % port)
        for idx, ip in enumerate(open_ips, 1):
            print("  %d. %s:%d" % (idx, ip, port))
    else:
        print("在该 IP 段内未发现开放 %d 端口的主机。" % port)

    if fp:
        try:
            fp.write("-" * 40 + "\n")
            fp.write("已扫描: %d/%d\n" % (done, total))
            fp.write("开放数量: %d\n" % len(open_ips))
            fp.write("总耗时: %.2f 秒\n" % duration)
            fp.close()
            print("结果已保存到: %s" % args.output)
        except Exception as exc:
            print("结果文件写入失败: %s" % exc)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("\n程序运行出错: %s" % exc)
