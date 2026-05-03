import os
import subprocess
import requests
import json
from autokfl.qemu import QEMU

def clone_linux_kernel(workdir):
    os.makedirs(workdir, exist_ok=True)
    
    kernel_url = "https://github.com/torvalds/linux.git"
    
    try:
        cmd = ["git", "clone", kernel_url]
        subprocess.run(cmd, cwd=workdir, check=True)
        print(f'Linux kernel cloned to {workdir}/linux')
    except subprocess.CalledProcessError as e:
        print(f'Git clone failed: {e}')
        raise

def get_crash_info(crash_id, workdir):
    url = f"https://syzkaller.appspot.com/bug?extid={crash_id}&json=1"
    response = requests.get(url)

    if response.status_code != 200:
        print(f'Failed to get crash info: {response.status_code}')
        raise

    with open(os.path.join(workdir, 'crash_info.json'), 'w') as f:
        json.dump(response.json(), f)

    return response.json()

def check_reproducibility(crash_info):
    crashes = crash_info.get('crashes', [])

    new_crashes = []
    for crash in crashes:
        if "syz-reproducer" in crash.keys() or "c-reproducer" in crash.keys():
            new_crashes.append(crash)
    crash_info['crashes'] = new_crashes

    return True if len(new_crashes) > 0 else False

def make_worktree(crash_id, crash_info, workdir):
    cur_dir = os.getcwd()

    crash = crash_info.get('crashes', [])[0]
    commit = crash.get('kernel-source-commit')
    os.chdir(os.path.join(workdir, 'linux'))

    cmd = ['git', 'worktree', 'list']
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    stdout = result.stdout

    worktrees = [[word for word in line.split(' ') if word][0] for line in stdout.split('\n') if line]
    
    for worktree in worktrees:
        if f'crash-{crash_id}' in worktree:
            print(f'Worktree {worktree} already exists')
            os.chdir(cur_dir)
            return
    
    try:
        cmd = ['git', 'worktree', 'add', f'../crash-{crash_id}', commit]
        subprocess.run(cmd, check=True)
        os.chdir(cur_dir)

        print(f'Worktree created at {os.path.join(workdir, f"crash-{crash_id}")}')
    except subprocess.CalledProcessError as e:
        print(f'Git worktree add failed: {e}')
        raise

def build_kernel(crash_id, crash_info, workdir):
    cur_dir = os.getcwd()

    os.chdir(os.path.join(workdir, f'crash-{crash_id}'))

    fn = os.listdir('.')
    check = True if 'vmlinux' in fn else False
    
    if check:
        print(f'Kernel already built')
        os.chdir(cur_dir)
        return

    crash = crash_info.get('crashes', [])[0]
    config = crash.get('kernel-config')

    try:
        print(f'Downloading config from {config}')
        url = f'https://syzkaller.appspot.com{config}'
        cmd = ['wget', url, '-O', '.config']
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f'Failed to download config: {e}')
        raise

    try:
        print(f'Making olddefconfig')
        cmd = ['make', 'olddefconfig']
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f'Failed to make olddefconfig: {e}')
        raise

    try:
        print(f'Building kernel')
        num_cores = os.cpu_count() or 1
        cmd = ['make', f'-j{num_cores}']
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f'Failed to make: {e}')
        raise

    try:
        print(f'Making cscope database')
        cmd = ['make', 'cscope']
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f'Failed to make cscope database: {e}')
        raise

    print(f'Kernel built successfully')
    os.chdir(cur_dir)

def build_image(workdir):
    url = 'https://raw.githubusercontent.com/google/syzkaller/refs/heads/master/tools/create-image.sh'

    cur_dir = os.getcwd()
    os.makedirs(os.path.join(workdir, 'image'), exist_ok=True)
    os.chdir(os.path.join(workdir, 'image'))

    check = True if 'trixie.img' in os.listdir('.') else False
    if check:
        print(f'Image already built')
        os.chdir(cur_dir)
        return

    try:
        print(f'Downloading create-image.sh from {url}')
        cmd = ['wget', url]
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f'Failed to download create-image.sh: {e}')
        raise

    try:
        print(f'Making create-image.sh executable')
        cmd = ['chmod', '+x', 'create-image.sh']
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f'Failed to make create-image.sh executable: {e}')
        raise

    try:
        is_root = os.geteuid() == 0
        if is_root:
            print(f'Building image (running as root)')
            cmd = ['./create-image.sh']
        else:
            print(f'Building image (requires root privileges)')
            cmd = ['sudo', './create-image.sh']
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f'Failed to build image: {e}')
        raise

    os.chdir(cur_dir)

def get_crepro(crash_info, workdir):
    crash = crash_info.get('crashes', [])[0]
    url = f'https://syzkaller.appspot.com{crash.get('c-reproducer')}'
    
    cur_dir = os.getcwd()
    os.chdir(workdir)

    try:
        print(f'Downloading c-reproducer from {url}')
        cmd = ['wget', url, '-O', 'repro.c']
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f'Failed to download c-reproducer: {e}')
        raise

    os.chdir(cur_dir)

def build_crash(crash_id, crash_info, workdir):
    crash_info = get_crash_info(crash_id)
    reproducible = check_reproducibility(crash_info)

    if reproducible:
        print(f'Crash {crash_id} is reproducible')

        make_worktree(crash_id, crash_info, workdir)
        build_kernel(crash_id, crash_info, workdir)
    else:
        print(f'Crash {crash_id} is not reproducible')
        return

    build_image(workdir)

    get_crepro(crash_info, workdir)

def read_file(file_path):
    file = ''
    with open(file_path, 'r') as f:
        for line_num, line in enumerate(f, start=1):
            line = line.replace('\n', '')
            file += f"{line_num}: {line}\n"
    return file
        

def get_kernel_version():
    cur_dir = os.getcwd()
    fn = os.listdir('.')
    dir_kernel = [f for f in fn if f.startswith('crash-')].pop()

    os.chdir(dir_kernel)
    result = subprocess.run(['make', 'kernelversion'], capture_output=True, text=True, check=True)
    version = result.stdout.strip()

    os.chdir(cur_dir)

    return version

def get_kernel_commit():
    cur_dir = os.getcwd()
    fn = os.listdir('.')
    dir_kernel = [f for f in fn if f.startswith('crash-')].pop()

    os.chdir(dir_kernel)

    result = subprocess.run(['git', 'rev-parse', 'HEAD'], capture_output=True, text=True, check=True)
    commit = result.stdout.strip()

    os.chdir(cur_dir)
    return commit

def get_kernel_arch():
    cur_dir = os.getcwd()
    fn = os.listdir('.')
    dir_kernel = [f for f in fn if f.startswith('crash-')].pop()

    os.chdir(dir_kernel)

    result = subprocess.run(['grep', '-oP', r'CONFIG_(X86_64|ARM64|ARM|RISCV)(?==y)', '.config'], capture_output=True, text=True, check=True)
    arch = result.stdout.strip().replace('CONFIG_', '')

    os.chdir(cur_dir)
    return arch

def reproduce_crash(workdir):
    cur_dir = os.getcwd()
    os.chdir(workdir)

    qemu = QEMU(workdir)
    qemu.run()
    
    qemu.send_repro('repro.c')
    qemu.compile_repro('repro.c')
    output, is_crash = qemu.run_repro('repro')

    if not is_crash:
        os.chdir(cur_dir)
        print('No crash detected')
        return
    
    callstack, entry_ctx, crash_ctx = qemu.extract_callstack(output)

    print('Crash reproduced successfully')
    print('[*] Callstack:')
    for line in callstack:
        print(f'    {line}')
    print('[*] Entry Context:')
    for line in entry_ctx:
        print(f'    {line}')
    print('[*] Crash Context:')
    for line in crash_ctx:
        print(f'    {line}')

    os.chdir(cur_dir)