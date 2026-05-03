import argparse
import os
from autokfl.util import clone_linux_kernel, get_crash_info, check_reproducibility, make_worktree, build_kernel, build_image, get_crepro, build_crash, reproduce_crash
from autokfl.autokfl import Autokfl
from autokfl.codebase import Codebase
from dotenv import load_dotenv

load_dotenv()

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workdir", type=str, required=True)
    parser.add_argument("--task", type=str, 
        choices=["clone_linux", 'build_kernel', 'build_image', 'build_crash', 'get_crepro', 'fl', 'repro_crash'], required=True)
    parser.add_argument("--crash_id", type=str, required=True)
    parser.add_argument("--model", type=str, choices=['claude', 'gpt', 'gemini'], default='gemini')
    parser.add_argument("--qemu_ssh", action='store_true')
    parser.add_argument("--run_qemu", action='store_true')

    return parser.parse_args()

def main():
    args = parse_args()
    workdir = args.workdir
    
    if args.task == 'clone_linux':
        clone_linux_kernel(workdir)
    elif args.task == 'build_kernel':
        crash_id = args.crash_id

        crash_info = get_crash_info(crash_id, workdir)
        reproducible = check_reproducibility(crash_info)

        if reproducible:
            print(f'Crash {crash_id} is reproducible')

            make_worktree(crash_id, crash_info, workdir)
            build_kernel(crash_id, crash_info, workdir)
        else:
            print(f'Crash {crash_id} is not reproducible')
    elif args.task == 'build_image':
        build_image(workdir)
    elif args.task == 'get_crepro':
        crash_id = args.crash_id
        crash_info = get_crash_info(crash_id, workdir)

        get_crepro(crash_info, workdir)
    elif args.task == 'build_crash':
        crash_id = args.crash_id
        crash_info = get_crash_info(crash_id, workdir)

        build_crash(crash_id, crash_info, workdir)
    elif args.task == 'repro_crash':

        reproduce_crash(workdir)
    elif args.task == 'fl':
        model = args.model
        path_callstack = 'callstack.json'
        path_repro = 'repro.c'
        path_crash_info = 'crash_info.json'

        codebase = Codebase()
        agent = Autokfl(workdir, model, codebase)
        agent.run(path_callstack, path_repro, path_crash_info)

if __name__ == "__main__":
    main()