def check_image_on_device(host, username, password, image_name, expected_size, results, lock):
    image_name = image_name.strip()  # Remove leading/trailing spaces
    try:
        ssh_cmd = f"sshpass -p {password} ssh -o StrictHostKeyChecking=no {username}@{host}"
        child = pexpect.spawn(ssh_cmd, timeout=20)
        child.expect([r">", r"#"])
        child.sendline("enable")
        idx = child.expect([r"Password:", r"#"])
        if idx == 0:
            child.sendline(password)
            child.expect(r"#")
        cmd = f"dir flash:{image_name}"
        child.sendline(cmd)
        child.expect([r"#", pexpect.EOF], timeout=10)
        output = child.before.decode() if isinstance(child.before, bytes) else child.before
        child.sendline("exit")
        child.close()

        # Check for unsuccessful lookup
        if "No such file or directory" in output or "Error listing directory" in output:
            result = {
                "device": host,
                "image_name": image_name,
                "image_present": False,
                "size_match": False
            }
        else:
            # Parse for image and size
            actual_size = None
            for line in output.splitlines():
                if image_name in line:
                    # Try to extract the size (first integer in the line)
                    parts = line.split()
                    for part in parts:
                        if part.isdigit():
                            actual_size = int(part)
                            break
                    if actual_size:
                        break
            if actual_size:
                size_match = actual_size == expected_size
                result = {
                    "device": host,
                    "image_name": image_name,
                    "image_present": True,
                    "actual_size": actual_size,
                    "expected_size": expected_size,
                    "size_match": size_match
                }
            else:
                result = {
                    "device": host,
                    "image_name": image_name,
                    "image_present": False,
                    "size_match": False
                }
        with lock:
            results.append(result)
        print(result)
    except Exception as e:
        with lock:
            results.append({"device": host, "error": str(e)})

def main():
    if len(sys.argv) != 2:
        print("Usage: python image_checker.py <input.yaml>")
        return
    config = load_yaml(sys.argv[1])
    username = config['username']
    password = config['password']
    image_name = config['image'].strip()  # Remove leading/trailing spaces
    expected_size = config['image_size']
    devices = config['devices']
    results = []
    threads = []
    lock = threading.Lock()
    for device in devices:
        t = threading.Thread(
            target=check_image_on_device,
            args=(device, username, password, image_name, expected_size, results, lock)
        )
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
