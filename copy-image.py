import yaml
import subprocess
import threading
import pexpect

# Path to your YAML file
YAML_FILE = 'upgrade_devices.yaml'
SUPERSWITCH_IP = None  # Will be set from YAML config

def ssh_copy_image(name, username, password, image_file, superswitch_ip):
    print(f"[{threading.current_thread().name}] Starting copy for device: {name}")
    # Use image_file as the filename directly
    copy_cmd = f'copy scp:{username}@{superswitch_ip}:/tmp/{image_file} flash:'
    copy_cmd_vrf = f'copy scp:{username}@{superswitch_ip}:/tmp/{image_file} vrf mgmt flash:'
    ssh_cmd = f"ssh {username}@{name} -o StrictHostKeyChecking=no"

    try:
        ssh_cmd = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {username}@{name}"
        print(f"[{threading.current_thread().name}] Connecting to {name}...")
        child = pexpect.spawn(ssh_cmd, encoding='utf-8', timeout=300)
        child.expect(['#', '>', pexpect.EOF, pexpect.TIMEOUT])
        child.sendline('enable')
        idx = child.expect(['[Pp]assword:', '#', pexpect.EOF, pexpect.TIMEOUT])
        if idx == 0:
            child.sendline(password)
            child.expect('#')
        print(f"[{threading.current_thread().name}] Sending copy command to {name}...")
        child.sendline(copy_cmd)
        idx = child.expect(['[Pp]assword:', '#', '% Error', pexpect.EOF, pexpect.TIMEOUT], timeout=300)
        if idx == 0:
            child.sendline(password)
            idx = child.expect(['Copy completed successfully.', '#', '% Error', pexpect.EOF, pexpect.TIMEOUT], timeout=1800)
        if idx == 2 or (isinstance(idx, int) and idx > 1 and '% Error' in child.before):
            print(f"[{threading.current_thread().name}] First copy failed, retrying with 'vrf mgmt'...")
            child.sendline(copy_cmd_vrf)
            idx = child.expect(['[Pp]assword:', '#', pexpect.EOF, pexpect.TIMEOUT], timeout=300)
            if idx == 0:
                child.sendline(password)
                idx = child.expect(['Copy completed successfully.', '#', pexpect.EOF, pexpect.TIMEOUT], timeout=1800)
            if idx == 0:
                print(f"[{threading.current_thread().name}] Success: {name}")
            else:
                print(f"[{threading.current_thread().name}] Copy may have failed or was incomplete for {name}")
        elif idx == 0 or idx == 1:
            print(f"[{threading.current_thread().name}] Waiting for SCP transfer to complete on {name}...")
            try:
                idx = child.expect(['Copy completed successfully.', '#', pexpect.EOF, pexpect.TIMEOUT], timeout=1800)
                if idx == 0:
                    print(f"[{threading.current_thread().name}] Success: {name}")
                else:
                    print(f"[{threading.current_thread().name}] Copy may have failed or was incomplete for {name}")
            except pexpect.TIMEOUT:
                print(f"[{threading.current_thread().name}] Timeout or error copying to {name}")
        child.close()
    except Exception as e:
        print(f"[{threading.current_thread().name}] Error copying to {name}: {e}")

def main():
    global SUPERSWITCH_IP
    print("Reading YAML configuration...")
    with open(YAML_FILE, 'r') as f:
        config = yaml.safe_load(f)

    username = config['username']
    password = config['password']
    SUPERSWITCH_IP = config.get('SUPERSWITCH_IP')
    if not SUPERSWITCH_IP:
        print("SUPERSWITCH_IP not found in YAML config.")
        return

    threads = []
    print("Starting image copy threads...")
    for group in config['groups']:
        image_file = group['image']
        for device in group['devices']:
            name = device['name']
            print(f"Spawning thread for device: {name}")
            t = threading.Thread(target=ssh_copy_image, args=(name, username, password, image_file, SUPERSWITCH_IP), name=f"Thread-{name}")
            t.start()
            threads.append(t)

    for t in threads:
        t.join()
    print("All threads completed.")

if __name__ == "__main__":
    main()

