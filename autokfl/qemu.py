import pexpect
import os
import subprocess
import sys
import json
import re
import getpass
from pathlib import Path

class QEMU:
    def __init__(self, workdir, ssh: bool=False):
        # self.cur_dir = os.getcwd()
        # self.workdir = workdir
        self.qemu = None
        self.ssh = ssh

    def _build_cmd(self):
        if self.ssh:
            try:
                home = Path.home()
                knwon_hosts = os.path.join(home, '.ssh', 'known_hosts')
                cmd = ['ssh-keygen', '-f', f'\'{knwon_hosts}\'', '-R', '\'[localhost]:2222\'']
                subprocess.run(cmd, check=True)
            except subprocess.CalledProcessError as e:
                pass

            cmd = []
            if getpass.getuser() != 'root':
                cmd.extend(['sudo'])
            cmd.extend(['ssh', '-i', 'image/trixie.id_rsa'])
            cmd.extend(['-p', '2222'])
            cmd.extend(['root@localhost'])
        else:
            fn = os.listdir('.')
            dir_kernel = [f for f in fn if f.startswith('crash-')].pop()

            cmd = []
            # if getpass.getuser() != 'root':
            #     cmd.extend(['sudo'])
            cmd.extend(['qemu-system-x86_64'])
            cmd.extend(['-m', '2G'])
            cmd.extend(['-smp', '2'])
            cmd.extend(['-kernel', f'{dir_kernel}/arch/x86/boot/bzImage'])
            cmd.extend(['-append', '\"root=/dev/sda console=ttyS0 earlyprintk=serial net.ifnames=0\"'])
            cmd.extend(['-drive', 'file=image/trixie.img,format=raw'])
            cmd.extend(['-snapshot'])
            cmd.extend(['-net', 'nic,model=e1000'])
            cmd.extend(['-net', 'user,host=10.0.2.10,hostfwd=tcp::2222-:22'])
            cmd.extend(['-nographic'])
            cmd.extend(['-enable-kvm'])
            print(' '.join(cmd))
            # exit(0)

        return cmd

    def _wait_for_login(self):

        if self.ssh:
            while True:
                index = self.qemu.expect(['yes/no', '~#'])
                output = self.qemu.before.decode()

                match index:
                    case 0: self.qemu.sendline('yes')
                    case 1: break
                    case _: raise Exception(f'Unexpected output: {output}')
        else:
            self.qemu.expect('login: ', timeout=300)
            # output = self.qemu.before.decode()
            self.qemu.sendline('root')
            self.qemu.expect('~#')
            output = self.qemu.before.decode()

        return output

    def _send_cmd(self, cmd):
        self.qemu.sendline(' '.join(cmd))
        index = self.qemu.expect(['~#', 'Kernel panic', pexpect.EOF])
        output = self.qemu.before.decode()

        return output, True if index in [1, 2] else False

    def send_repro(self, file_path: str='repro.c'):
        cmd = []
        if getpass.getuser() != 'root':
            cmd.extend(['sudo'])
        cmd.extend(['scp', '-i', 'image/trixie.id_rsa'])
        cmd.extend(['-P', '2222'])
        cmd.extend([file_path, 'root@localhost:/root/'])

        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f'Failed to send file: {e}')

    def compile_repro(self, file_path: str='repro.c'):
        cmd = []
        cmd.extend(['gcc', file_path, '-o', 'repro'])
        return self._send_cmd(cmd)

    def run_repro(self, file_path: str='repro'):
        cmd = []
        cmd.extend([f'./{file_path}'])
        return self._send_cmd(cmd)

    def _clean_line(self, line):
            line = line.replace('? ', '')
            return re.sub(r'\[\s*\d+\.\d+\]\[T\d+\]\s*', '', line)

    def _parse_registers(self, lines):
        result = []

        for line in lines:
            # pattern = r'([A-Z0-9]+):\s+([^\s]+(?:[:\s]+[^\s]+)*?)(?=\s+[A-Z0-9]+:|$)'
            pattern = r'([A-Z0-9_]+):\s+([^\s]+(?:\s+[^\s]+)*?)(?=\s+[A-Z0-9_]+:|$)'
            matches = re.finditer(pattern, line)
            
            for match in matches:
                reg_name = match.group(1)
                reg_value = match.group(2).strip()
                result.append((reg_name, reg_value))

        return result

    def _convert_source_code(self, callstack):
        fn = os.listdir('.')
        dir_kernel = [f for f in fn if f.startswith('crash-')].pop()

        def faddr2line(lines):
            cmd = []
            cmd.extend([f'{dir_kernel}/scripts/faddr2line'])
            cmd.extend([f'{dir_kernel}/vmlinux'])
            for line in lines:
                cmd.extend([line])

            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            lines = result.stdout.split('\n\n')
    
            callstack = []
            for line in lines:
                sublines = [_ for _ in line.split('\n') if len(_) > 0]
                interpreted = {}
                for idx, subline in enumerate(sublines):
                    if idx == 0:
                        tmp = subline.split('+')
                        function_name = tmp[0]
                        tmp = tmp[1].split('/')
                        offset = tmp[0]
                        function_size = tmp[1]
                        interpreted['function_name'] = function_name
                        interpreted['offset'] = offset
                        interpreted['function_size'] = function_size
                        interpreted['src'] = []
                    else:
                        # rectified.extend([_ for _ in subline.split(':')])
                        tmp = subline.split(':')
                        location = tmp[0]
                        line = tmp[1].split(' ')

                        if len(line) == 1: discriminator = None
                        else: discriminator = line[1] + ' ' + line[2]

                        line = int(line[0])
                        interpreted['src'].append({
                            'location': location,
                            'line': line,
                            'discriminator': discriminator
                        })
                callstack.append(interpreted)
            return callstack

        result = faddr2line(callstack)
        return result

    def extract_callstack(self, log):
        lines = [line.strip() for line in log.split('\n')]
        indices = []
        for idx, line in enumerate(lines):
            if 'Call Trace:' in line:
                indices.append(idx)
        idx = indices[-1]
        lines = lines[idx:]
    
        state = 'INIT'  # INIT -> CALLSTACK -> ENTRY_CTX -> EXIT_CTX
        callstack = []
        entry_ctx = []
        exit_ctx = []

        for line in lines:
            if state == 'INIT':
                if '<TASK>' in line:
                    state = 'CALLSTACK'
            
            elif state == 'CALLSTACK':
                if '</TASK>' in line:
                    state = 'ENTRY_CTX'
                elif 'RIP' in line:
                    state = 'ENTRY_CTX'
                    entry_ctx.append(self._clean_line(line))
                else:
                    callstack.append(self._clean_line(line))
            
            elif state == 'ENTRY_CTX':
                if 'RIP' in line:
                    state = 'EXIT_CTX'
                    exit_ctx.append(self._clean_line(line))
                else:
                    entry_ctx.append(self._clean_line(line))
            
            elif state == 'EXIT_CTX':
                cleaned = self._clean_line(line)
                if cleaned:
                    exit_ctx.append(cleaned)
    
        idx = entry_ctx.index('</TASK>')
        entry_ctx = entry_ctx[:idx]

        entry_ctx = self._parse_registers(entry_ctx)
        exit_ctx = self._parse_registers(exit_ctx)

        for ctx in exit_ctx:
            if ctx[0] == 'RIP':
                crash_location = ctx[1].split(':')[1]
                callstack = [crash_location] + callstack
                break

        callstack = self._convert_source_code(callstack)
        
        data = {
            'callstack': callstack,
            'entry_ctx': entry_ctx,
            'exit_ctx': exit_ctx
        }
        with open('callstack.json', 'w') as f:
            json.dump(data, f)
                    
        return callstack, entry_ctx, exit_ctx


    def run(self):
        cmd = self._build_cmd()
        
        self.qemu = pexpect.spawn(' '.join(cmd))
        # self.qemu.logfile = sys.stdout.buffer

        _ = self._wait_for_login()

    def close(self):
        if self.qemu:
            self.qemu.close()
            self.qemu = None