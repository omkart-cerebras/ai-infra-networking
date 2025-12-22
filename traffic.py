#!/usr/bin/env python3
'''
This is a adhoc script for running quick network commissioning test. You need IPs for the AWS instances to run iperf traffic to in respective VPCs
The run_traffic_test() spawns threads (iperf servers first followed by ping and iperf client), each of which calls run_command(label, cmd) to run one command and log output.
After all threads/processes finish, it builds a summary and exits.
If Ctrl+C is pressed, handle_interrupt orchestrates a graceful shutdown, summarizes, and exits; second Ctrl+C forces an immediate exit.
Currently its hardcoded to work for below number of IPs and PEM which can be modified as needed.
ips:
  IP1:   # Deploy node
  IP2:       # User node rack 1
  IP3:      # User node rack 2
  IP4:      # Inference-us-west-1
  IP5:      # Inference-us-west-2
  IP6:     # VAST node
  IP7:     # MGMT node
  IP8:        # DCV node

pems:
  PEM1: 
  PEM2: 
  
'''

import subprocess
import threading
import time
import os
import yaml
import signal
import sys
import traceback
from collections import deque
from datetime import datetime

def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def run_traffic_test(yaml_file, duration_min, username, log_dir, collect_only=False):
    """
    Runs ping and iperf3 traffic tests using configuration from a YAML file.
    Timestamped logging, SSH -n, process timeouts/force-kill, and summary
    generated strictly AFTER all tests have stopped.
    """

    # ===== Load Config =====
    with open(yaml_file, "r") as f:
        cfg = yaml.safe_load(f)

    ips = cfg["ips"]
    pems = cfg["pems"]

    IP1, IP2, IP3, IP4, IP5 = ips["IP1"], ips["IP2"], ips["IP3"], ips["IP4"], ips["IP5"]
    IP6, IP7, IP8 = ips["IP6"], ips["IP7"], ips["IP8"]
    PEM1, PEM2 = pems["PEM1"], pems["PEM2"]

    duration_sec = duration_min * 60
    print(f"[{ts()}] [INFO] Running tests for {duration_min} minutes ({duration_sec}s). Logs in {os.path.abspath(log_dir)}")

    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    processes = []
    processes_lock = threading.Lock()
    stop_flag = False

    # ===== Helper: run command and capture log with timeouts =====
    def run_command(label, cmd):
        log_path = os.path.join(log_dir, f"{label}.log")
        print(f"[{ts()}] [START] {label}")
        try:
            with open(log_path, "w") as f:
                f.write(f"===== {label} started at {ts()} =====\n")
                try:
                    proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        shell=True,
                        bufsize=1,
                    )
                except Exception as e:
                    f.write(f"[{ts()}] [CRITICAL] Failed to start {label}: {e}\n")
                    traceback.print_exc(file=f)
                    print(f"[{ts()}] [CRITICAL] Failed to start {label}: {e}")
                    return

                with processes_lock:
                    processes.append(proc)

                try:
                    start_time = time.time()
                    for line in iter(proc.stdout.readline, ''):
                        if not line and proc.poll() is not None:
                            break
                        if line:
                            f.write(f"[{ts()}] {line}")
                            f.flush()
                        # Safety overrun: kill if exceeds nominal duration by 30s
                        if time.time() - start_time > duration_sec + 30:
                            f.write(f"[{ts()}] [TIMEOUT] {label} exceeded {duration_sec}s — killing.\n")
                            proc.kill()
                            break

                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        f.write(f"[{ts()}] [WARN] {label} didn’t exit — forcing kill.\n")
                        proc.kill()

                except Exception as e:
                    f.write(f"[{ts()}] [ERROR] {label} execution error: {e}\n")
                    traceback.print_exc(file=f)
                finally:
                    try:
                        if proc.poll() is None:
                            proc.kill()
                    except Exception:
                        pass

                f.write(f"===== {label} ended at {ts()} =====\n")
                f.flush()
        except Exception as e:
            print(f"[{ts()}] [CRITICAL] Logging failed for {label}: {e}")
        print(f"[{ts()}] [STOP] {label}")

    def build_summary():
        print(f"[{ts()}] [INFO] Creating Summary now ...")
        summary_file = os.path.join(log_dir, "summary.log")
        try:
            with open(summary_file, "w") as s:
                s.write(f"===== Summary generated at {ts()} =====\n")
                for log_name in sorted(os.listdir(log_dir)):
                    if not log_name.endswith(".log") or log_name == "summary.log":
                        continue
                    log_path = os.path.join(log_dir, log_name)
                    s.write(f"\n===== {log_name} =====\n")
                    try:
                        with open(log_path, 'rb') as f:
                            tail_lines = deque(f, maxlen=20)
                        s.writelines(line.decode('utf-8', errors='ignore') for line in tail_lines)
                    except Exception as e:
                        s.write(f"[{ts()}] [WARN] Could not read {log_name}: {e}\n")
                    s.write("========================\n")
            print(f"[{ts()}] [INFO] Summary written to {summary_file}")
        except Exception as e:
            print(f"[{ts()}] [WARN] Failed to write summary: {e}")

    # ===== Force stop helpers =====
    def terminate_all_processes():
        with processes_lock:
            for p in processes:
                try:
                    if p.poll() is None:
                        p.terminate()
                except Exception:
                    pass

    def kill_all_processes():
        with processes_lock:
            for p in processes:
                try:
                    if p.poll() is None:
                        p.kill()
                except Exception:
                    pass

    # ===== Signal handler =====
    def handle_interrupt(sig, frame):
        nonlocal stop_flag
        if stop_flag:
            print(f"[{ts()}] [WARN] Second interrupt — force exit.")
            os._exit(1)
        stop_flag = True
        print(f"\n[{ts()}] [INFO] Ctrl+C detected. Stopping all tests gracefully...")

        terminate_all_processes()
        time.sleep(2)
        kill_all_processes()

        if not collect_only:
            print(f"[{ts()}] [INFO] Attempting to stop remote iperf3 servers...")
            try:
                subprocess.run(
                    f"ssh -o StrictHostKeyChecking=no {username}@{IP1} "
                    f"\"sudo ssh {IP2} 'ssh -i {PEM1} ec2-user@{IP4} pkill -9 iperf3'; "
                    f"sudo ssh {IP3} 'ssh -i {PEM2} ec2-user@{IP5} pkill -9 iperf3'\"",
                    shell=True,
                    timeout=15,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                print(f"[{ts()}] [INFO] Remote iperf3 servers stopped.")
            except Exception as e:
                print(f"[{ts()}] [WARN] Failed to stop iperf servers: {e}")

        # Ensure all processes have ended before summary
        wait_for_all_processes_and_threads(final_wait=True)
        build_summary()
        print(f"[{ts()}] [INFO] All threads finished. Exiting cleanly.")
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_interrupt)

    # ===== Start iperf servers (if not collect-only) =====
    server_threads = []
    if not collect_only:
        server_cmds = {
            "IperfServer_Inf1": (
                f"ssh -o StrictHostKeyChecking=no {username}@{IP1} "
                f"\"sudo ssh {IP2} 'ssh -i {PEM1} ec2-user@{IP4} "
                f"\\\"timeout {duration_sec}s iperf3 -p 55665 -s\\\"'\""
            ),
            "IperfServer_Inf2": (
                f"ssh -o StrictHostKeyChecking=no {username}@{IP1} "
                f"\"sudo ssh {IP3} 'ssh -i {PEM2} ec2-user@{IP5} "
                f"\\\"timeout {duration_sec}s iperf3 -p 55665 -s\\\"'\""
            )
        }

        for label, cmd in server_cmds.items():
            t = threading.Thread(target=run_command, args=(label, cmd), name=label)
            server_threads.append(t)
            t.start()
            time.sleep(1)

        print(f"[{ts()}] [INFO] Waiting 5s for iperf3 servers to initialize...")
        time.sleep(5)

    # ===== Define ping + iperf clients (use ssh -n to avoid stdin blocking) =====
    tests = {
        "Ping1_ConnectVPN_to_Deploy": f"ping -i {duration_sec} {IP1}",
        "Ping2_Dev_to_Deploy": f"ssh -n omkart@omkart-dev 'ping -w {duration_sec} {IP1}'",
        "Ping3_Dev_to_DCV": f"ssh -n omkart@omkart-dev 'ping -w {duration_sec} {IP8}'",
        "Ping4_Dev_to_UserNodes": f"ssh -n omkart@omkart-dev 'ping -w {duration_sec} {IP2}; ping -w {duration_sec} {IP3}'",
        "Ping5_VASTC_to_User1": f"ssh -n {username}@{IP1} \"sudo ssh -n {IP2} 'ping -w {duration_sec} {IP6}'\"",
        "Ping6_MGMTC_to_User2": f"ssh -n {username}@{IP1} \"sudo ssh -n {IP3} 'ping -w {duration_sec} {IP7}'\"",
    }

    if not collect_only:
        tests.update({
            "Iperf7_User1_to_Inf1": f"ssh -n {username}@{IP1} \"sudo ssh -n {IP2} 'iperf3 -p 55665 -b 7M -c {IP4} -P 64 -t {duration_sec} --get-server-output'\"",
            "Iperf8_User2_to_Inf2": f"ssh -n {username}@{IP1} \"sudo ssh -n {IP3} 'iperf3 -p 55665 -b 7M -c {IP5} -P 64 -t {duration_sec} --get-server-output'\""
        })

    # ===== Run tests =====
    threads = []
    for label, cmd in tests.items():
        t = threading.Thread(target=run_command, args=(label, cmd), name=label)
        threads.append(t)
        t.start()
        time.sleep(0.5)

    # ===== Wait/Enforce: processes must end before summary =====
    def wait_for_all_processes_and_threads(final_wait=False):
        """
        Wait until all tracked processes exit (with a hard deadline),
        then join all threads (no timeout in final_wait mode).
        """
        deadline = time.time() + duration_sec + 60  # duration + 60s buffer
        while True:
            with processes_lock:
                alive = [p for p in processes if p.poll() is None]
            if not alive:
                break
            if not final_wait and time.time() > deadline:
                # Pre-summary phase: don't block forever — warn and break
                print(f"[{ts()}] [WARN] Some processes still alive past deadline; will attempt to kill before summary.")
                break
            if final_wait and time.time() > deadline:
                print(f"[{ts()}] [WARN] Final wait exceeded; force killing remaining processes.")
                kill_all_processes()
                break
            time.sleep(1)

        # Now join threads
        if final_wait:
            for t in threads:
                t.join()
            for t in server_threads:
                t.join()
        else:
            # non-final phase (not used currently), keep time-bounded joins
            for t in threads:
                t.join(timeout=5)
            for t in server_threads:
                t.join(timeout=5)
            for t in threads + server_threads:
                if t.is_alive():
                    print(f"[{ts()}] [WARN] Thread {t.name} still running after join timeout.")

    # Normal completion path: wait fully, then summarize
    wait_for_all_processes_and_threads(final_wait=True)
    build_summary()
    print(f"[{ts()}] [INFO] All tests completed normally.")

# ===== Allow standalone CLI run =====
if __name__ == "__main__":
    try:
        yaml_file = input("Enter YAML file (e.g., iperf_config.yaml): ").strip()
        duration_min = int(input("Enter duration of test (in minutes): ").strip())
        username = input("Enter username for IP1: ").strip()
        log_dir = input("Enter log directory name (e.g., test_logs): ").strip()
        collect_only_input = input("Run pings only (y/n)? ").strip().lower()
        collect_only = collect_only_input == "y"

        run_traffic_test(yaml_file, duration_min, username, log_dir, collect_only)
    except KeyboardInterrupt:
        print(f"\n[{ts()}] [INFO] Interrupted manually. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"[{ts()}] [FATAL] Unhandled exception: {e}")
        traceback.print_exc()
        sys.exit(1)
