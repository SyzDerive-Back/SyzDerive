from math import trunc
import re
import os, stat, sys
import json
import time
from SyzDerive.modules.deploy.case import Case
import requests
import shutil
import logging
import SyzDerive.interface.utilities as utilities

from SyzDerive.modules.syzbotCrawler import syzbot_host_url, syzbot_bug_base_url
from subprocess import call, run, Popen, PIPE, STDOUT
from SyzDerive.interface.utilities import URL, chmodX
from dateutil import parser as time_parser
from .worker import Workers

syz_config_template="""
{{ 
        "target": "linux/amd64/{8}",
        "http": "0.0.0.0:{5}",
        "workdir": "{0}/workdir",
        "kernel_obj": "{1}",
        "image": "{2}/stretch.img",
        "sshkey": "{2}/stretch.img.key",
        "syzkaller": "{0}",
        "procs": 8,
        "mutatetime": {12},
        "type": "qemu",
        "testcase": "{0}/workdir/testcase-{4}",
        "analyzer_dir": "{6}",
        "time_limit": "{7}",
        "store_read": {10},
        "grebe_struct": {11},
        "calltrace_path": {14},
        "vm": {{
                "count": {9},
                "kernel": "{1}/arch/x86/boot/bzImage",
                "cpu": 2,
                "mem": 2048
        }},
        "enable_syscalls": [
            {3}
        ],
        "email_addrs": [
            {13}
        ]
}}"""


class Deployer(Workers):
    def __init__(self, hash_val, index, parallel_run, parallel_max, debug=False, force=False, port=53777, replay='incomplete', linux_index=-1, time=8, key_syscall=None, kernel_fuzzing=False, mutate_time=500, reproduce=False, alert=[], gdb_port=1235, qemu_monitor_port=9700, max_compiling_kernel=-1, store_read=True):
        Workers.__init__(self, index, parallel_max, debug, force, port, replay, linux_index, time, key_syscall, kernel_fuzzing, reproduce, alert, gdb_port, qemu_monitor_port, max_compiling_kernel, store_read)
        self.save_linux_folder = '/disk0/'
        os.makedirs(self.save_linux_folder, exist_ok=True)
        self.clone_linux(hash_val)
        self.mutate_time = mutate_time
    
    def init_replay_crash(self, hash_val):
        chmodX("SyzDerive/scripts/init-replay.sh")
        self.logger.info("run: scripts/init-replay.sh {} {}".format(self.catalog, hash_val))
        call(["SyzDerive/scripts/init-replay.sh", self.catalog, hash_val])

    def deploy(self, hash_val, case):
        self.setup_hash(hash_val)
        self.project_path = os.getcwd()
        self.package_path = os.path.join(self.project_path, "SyzDerive")
        self.current_case_path = "{}/work/{}/{}".format(self.project_path, self.catalog, hash_val[:7])
        self.image_path = "{}/img".format(self.current_case_path)
        self.syzkaller_path = "{}/gopath/src/github.com/google/syzkaller".format(self.current_case_path)
        self.kernel_path = "{}/linux".format(self.current_case_path)
        self.arch = "amd64"
        if utilities.regx_match(r'386', case["manager"]):
            self.arch = "386"
        self.logger.info(hash_val)

        if self.replay:
            self.init_replay_crash(hash_val[:7])

        succeed = self.__create_dir_for_case()

        self.basic_info_folder = os.path.join(self.current_case_path,'basic_info')
        os.makedirs(self.basic_info_folder, exist_ok=True)

        if not self.finished_case_basic_info_save(hash_val, 'incomplete'):

            if case['config'] != None:
                r = utilities.request_get(case["config"])
                config_save = open(os.path.join(self.basic_info_folder,'config'), 'w')
                config_save.write(r.text)
                config_save.close()

            if case['syz_repro'] != None:
                req = utilities.request_get(case["syz_repro"])
                syz_repro = open(os.path.join(self.basic_info_folder,'syz_repro'), 'w')
                syz_repro.write(req.content.decode("utf-8"))
                syz_repro.close()

            if case['log'] != None:
                r = utilities.request_get(case['log'])
                with open(os.path.join(self.basic_info_folder,'log'), "w") as f:
                    f.write(r.text)
                f.close()

            if case['c_repro'] != None:
                r = utilities.request_get(case['c_repro'])
                with open(os.path.join(self.basic_info_folder,'c_repro'), "w") as f:
                    f.write(r.text)
                f.close()

            if case['report'] != None:
                r = utilities.request_get(case['report'])
                with open(os.path.join(self.basic_info_folder,'report'), "w") as f:
                    f.write(r.text)
                f.close()
                report = "".join(r.text)
                trace = self.get_cg(report)
                open(os.path.join(self.basic_info_folder,"report_cg"), "w").write(trace)

            self.create_finished_case_basic_info_save_stamp()

        self.calltrace_path = "\"{}\"".format(os.path.join(self.basic_info_folder,"report_cg"))

        with open(os.path.join(self.basic_info_folder,'config'), 'r') as f:
            config_text = f.read()
        self.compiler = utilities.set_compiler_version(time_parser.parse(case["time"]),config_text)

        if self.force:
            self.cleanup_built_kernel(hash_val)
            self.cleanup_built_syzkaller(hash_val)
            if self.kernel_fuzzing:
                self.cleanup_reproduced_ori_poc(hash_val)
                self.cleanup_finished_fuzzing(hash_val)
            if self.reproduce_ori_bug:
                self.cleanup_reproduced_ori_poc(hash_val)

        self.case_logger = self.__init_case_logger("{}-log".format(hash_val))
        self.case_info_logger = self.__init_case_info_logger("{}-info".format(hash_val))

        url = syzbot_host_url + syzbot_bug_base_url + hash_val
        self.case_info_logger.info(url)
        self.case_info_logger.info("pid: {}".format(os.getpid()))

        i386 = None
        if utilities.regx_match(r'386', case["manager"]):
            i386 = True
        
        self.init_crash_checker(self.ssh_port)

        need_patch = 0
        r = self.__run_delopy_script(hash_val[:7], case, need_patch)
        if r != 0:
            self.logger.error("Error occur in deploy.sh")
            self.__move_to_error()
            self.create_bad_deploy_stamp()
            return

        with open(os.path.join(self.basic_info_folder,'syz_repro'), 'r') as f:
            req = f.read()

        self.__write_config(req, hash_val[:7])

        if self.kernel_fuzzing:
            if not self.reproduced_ori_poc(hash_val, 'incomplete'):
                self.do_reproducing_ori_poc(case, hash_val, i386)
            if not self.finished_fuzzing(hash_val, 'incomplete'):
                exitcode = self.run_syzkaller(hash_val)
                if exitcode !=0:
                    self.create_bad_fuzzing_stamp()
                    self.logger.info("{} error in fuzzing".format(hash_val[:7]))
                    self.__move_to_error()
                    return
                self.__copy_crashes()
                self.create_finished_fuzzing_stamp()
            else:
                self.__move_to_analyzing()
                self.logger.info("{} has finished fuzzing".format(hash_val[:7]))
        return self.index

    def clone_linux(self,hash_val):
        self.__run_linux_clone_script(hash_val)

    def run_syzkaller(self, hash_val):
        self.logger.info("run syzkaller".format(self.index))
        syzkaller = os.path.join(self.syzkaller_path, "bin/syz-manager")
        exitcode = 4
        for _ in range(0, 3):
            if self.logger.level == logging.DEBUG:
                p = Popen([syzkaller, 
                            "--config={}/workdir/{}-poc.cfg".format(self.syzkaller_path, hash_val[:7]), 
                            "-debug", 
                            "-poc",
                            ],
                    stdout=PIPE,
                    stderr=STDOUT
                    )
                with p.stdout:
                    self.__log_subprocess_output(p.stdout, logging.INFO)
                exitcode = p.wait()
            else:
                p = Popen([syzkaller, 
                            "--config={}/workdir/{}-poc.cfg".format(self.syzkaller_path, hash_val[:7]), 
                            "-poc",
                            ],
                    stdout=PIPE,
                    stderr=STDOUT
                    )
                with p.stdout:
                    self.__log_subprocess_output(p.stdout, logging.INFO)
                exitcode = p.wait()
            if exitcode != 4:
                break
        self.logger.info("syzkaller is done with exitcode {}".format(exitcode))
        if exitcode == 3:
            if self.correctTemplate() and self.compileTemplate():
                exitcode = self.run_syzkaller(hash_val)
        return exitcode
    
    def compileTemplate(self):
        target = os.path.join(self.package_path, "scripts/syz-compile.sh")
        chmodX(target)
        self.logger.info("run: scripts/syz-compile.sh")
        p = Popen([target, self.current_case_path ,self.arch],
                stdout=PIPE,
                stderr=STDOUT
                )
        with p.stdout:
            self.__log_subprocess_output(p.stdout, logging.INFO)
        exitcode = p.wait()
        self.logger.info("script/syz-compile.sh is done with exitcode {}".format(exitcode))
        return exitcode == 0
    
    def correctTemplate(self):
        find_it = False
        pattern_type = utilities.SYSCALL
        text = ''
        pattern = ''
        try:
            path = os.path.join(self.syzkaller_path, 'CorrectTemplate')
            f = open(path, 'r')
            text = f.readline()
            if len(text) == 0:
                self.logger.info("Error: CorrectTemplate is empty")
                return find_it
        except:
            return find_it
        
        if text.find('syscall:') != -1:
            pattern = text.split(':')[1]
            pattern_type = utilities.SYSCALL
            pattern = pattern + "\("
        if text.find('arg:') != -1:
            pattern = text.split(':')[1]
            pattern_type = utilities.STRUCT
            i = pattern.find('[')
            if i != -1:
                pattern = "type " + pattern[:i]
            else:
                pattern = pattern + " {"
        
        search_path="sys/linux"
        extension=".txt"
        ori_syzkaller_path = os.path.join(self.current_case_path, "poc/gopath/src/github.com/google/syzkaller")
        regx_pattern = "^"+pattern
        src = os.path.join(ori_syzkaller_path, search_path)
        dst = os.path.join(self.syzkaller_path, search_path)
        find_it = self.syncFilesByPattern(regx_pattern, pattern_type, src, dst, extension)
        return find_it

    def syncFilesByPattern(self, pattern, pattern_type, src, dst, ends):
        find_it = False
        data = []
        target_file = ''
        brackets = -1

        if not os.path.isdir(src):
            self.logger.info("{} do not exist".format(src))
            return find_it
        for file_name in os.listdir(src):
            if file_name.endswith(ends):
                find_it = False
                f = open(os.path.join(src, file_name), "r")
                text = f.readlines()
                f.close()
                for line in text:
                    if utilities.regx_match(pattern, line):
                        data.append(line)
                        find_it = True
                        if pattern_type == utilities.FUNC_DEF and line.find('{') != -1:
                            if brackets == -1:
                                brackets = 1
                        continue

                    if find_it:
                        if pattern_type == utilities.SYSCALL or (pattern_type == utilities.STRUCT and line == "\n"):
                            break
                        data.append(line)
                        if pattern_type == utilities.FUNC_DEF:
                            if line.find('{') != -1:
                                if brackets == -1:
                                    brackets = 0
                                brackets += 1
                            if line.find('}') != -1:
                                brackets -= 1
                            if brackets == 0:
                                break
                if find_it:
                    target_file = file_name
                    break
        
        if not os.path.isdir(dst):
            self.logger.info("{} do not exist".format(dst))
            return False
        for file_name in os.listdir(dst):
            if file_name.endswith(ends):
                #print(file_name)
                find_it = False
                start = 0
                end = 0
                f = open(os.path.join(dst, file_name), "r")
                text = f.readlines()
                f.close()
                for i in range(0, len(text)):
                    line = text[i]
                    if utilities.regx_match(pattern, line):
                        start = i
                        find_it = True
                        continue
                    
                    if find_it:
                        end = i
                        if pattern_type == utilities.SYSCALL or (pattern_type == utilities.STRUCT and line == "\n"):
                            break
            
                if find_it:
                    f = open(os.path.join(dst, file_name), "w")
                    new_data = []
                    new_data.extend(text[:start])
                    new_data.extend(data)
                    new_data.extend(text[end:])
                    f.writelines(new_data)
                    f.close()
                    break
                elif target_file == file_name:
                    f = open(os.path.join(dst, file_name), "w")
                    new_data = []
                    new_data.extend(text)
                    new_data.extend(data)
                    f.writelines(new_data)
                    f.close()
                    find_it = True
                    break
        if pattern_type == utilities.SYSCALL:
            if utilities.regx_match(r'^syz_', pattern):
                regx_pattern = "^"+pattern
                src = os.path.join(self.current_case_path, "poc/gopath/src/github.com/google/syzkaller/executor")
                dst = os.path.join(self.syzkaller_path, "executor")
                file_ends = "common_linux.h"
                self.syncFilesByPattern(regx_pattern, utilities.FUNC_DEF, src, dst, file_ends)
        return find_it

    def getSubStruct(self, struct_data):
        regx_field = r'\W*([a-zA-Z0-9\[\]_]+)\W+([a-zA-Z0-9\[\]_, ]+)'
        start = False
        end = False
        res = []
        for line in struct_data:
            if line.find('{') != -1:
                start = True
            if line.find('}') != -1:
                end = True
            if end:
                break
            if start:
                field_type = utilities.regx_get(regx_field, line, 1)
                struct_list = self.extractStruct(field_type)
                if len(struct_list) > 0:
                    res.extend(struct_list)
        return res

    def extractStruct(self, text):
        trivial_type = ["int8", "int16", "int32", "int64", "int16be", "int32be", "int64be", "intptr",
                        "in", "out", "inout", "dec", "hex", "oct", "fmt", "string", "target", 
                        "x86_real", "x86_16", "x86_32", "x86_64", "arm64", "text", "proc", "ptr", "ptr64",
                        "inet", "pseudo", "csum", "vma", "vma64", "flags", "const", "array", "void"
                        "len", "bytesize", "bytesize2", "bytesize4", "bytesize8", "bitsize", "offsetof"]
    
    def __run_linux_clone_script(self,hash_val):
        chmodX("SyzDerive/scripts/linux-clone.sh")
        index = str(self.index)
        self.logger.info("run: scripts/linux-clone.sh {} {} {}".format(self.save_linux_folder, self.linux_folder, hash_val[:7]))
        call(["SyzDerive/scripts/linux-clone.sh", self.save_linux_folder, self.linux_folder, hash_val[:7]])

    def __run_delopy_script(self, hash_val, case, kasan_patch=0):
        commit = case["commit"]
        syzkaller = case["syzkaller"]
        config = case["config"]
        testcase = case["syz_repro"]
        time = case["time"]
        self.case_info_logger.info("\ncommit: {}\nsyzkaller: {}\nconfig: {}\ntestcase: {}\ntime: {}\narch: {}".format(commit,syzkaller,config,testcase,time,self.arch))

        case_time = time_parser.parse(time)
        if self.image_switching_date <= case_time:
            image = "stretch"
        else:
            image = "wheezy"
        target = os.path.join(self.package_path, "scripts/deploy.sh")
        chmodX(target)
        index = str(self.index)
        self.logger.info("run: scripts/deploy.sh")
        p = Popen([target, self.linux_folder, hash_val, commit, syzkaller, config, testcase, self.hash_val[:7], self.catalog, image, self.arch, self.compiler, str(self.max_compiling_kernel), self.save_linux_folder],
                stdout=PIPE,
                stderr=STDOUT
                )
        with p.stdout:
            self.__log_subprocess_output(p.stdout, logging.INFO)
        exitcode = p.wait()
        self.logger.info("script/deploy.sh is done with exitcode {}".format(exitcode))
        return exitcode
    
    def __write_config(self, testcase, hash_val):
        dependent_syscalls = []
        syscalls = self.__extract_syscalls(testcase)
        if syscalls == []:
            self.logger.info("No syscalls found in testcase: {}".format(testcase))
            return -1
        syzkaller_path = self.syzkaller_path
        for each in syscalls:
            dependent_syscalls.extend(self.__extract_dependent_syscalls(each, syzkaller_path))
        if len(dependent_syscalls) < 1:
            self.logger.info("Cannot find dependent syscalls for\n{}\nTry to continue without them".format(testcase))
        new_syscalls = syscalls.copy()
        new_syscalls.extend(dependent_syscalls)
        new_syscalls = utilities.unique(new_syscalls)
        enable_syscalls = "\"" + "\",\n\t\"".join(new_syscalls) + "\""
        email_addrs_list = [" "]
        email_addrs = "\"" + "\",\n\t\"".join(email_addrs_list) + "\""
    
        syzkaller_path = self.syzkaller_path
        self.grebe_struct = "\" \""
        syz_config = syz_config_template.format(syzkaller_path, 
                                                self.kernel_path, 
                                                self.image_path, 
                                                enable_syscalls, 
                                                hash_val, 
                                                self.ssh_port, 
                                                self.current_case_path, 
                                                self.time_limit, 
                                                self.arch, 
                                                self.max_qemu_for_one_case, 
                                                str(self.store_read).lower(),
                                                self.grebe_struct,
                                                self.mutate_time,
                                                email_addrs,
                                                self.calltrace_path)
        f = open(os.path.join(syzkaller_path, "workdir/{}-poc.cfg".format(hash_val)), "w")
        f.writelines(syz_config)
        f.close()

    def __extract_syscalls(self, testcase):
        res = []
        res_add_key_syscall = []
        text = testcase.split('\n')
        for line in text:
            if len(line)==0 or line[0] == '#':
                continue

            m = re.search(r'(\w+(\$\w+)?)\(', line)
            if m == None or len(m.groups()) == 0:
                self.logger.info("Failed to extract syscall from {}".format(self.index, line))
                return res
            syscall = m.groups()[0]
            res.append(syscall)
        
        res_add_key_syscall = res.copy()
        if self.key_syscall:
            with open(os.path.join(self.package_path,'resources',self.key_syscall), 'r', encoding='utf-8') as file:
                key_syscall_dict = json.load(file)
                for test_syscall in res:
                    res_add_key_syscall.append(test_syscall)
                    for bug_type in ["UAF","OOB","IF"]:
                        for bug_syscall_seq in key_syscall_dict[bug_type]:
                            if test_syscall.split('$')[0] in bug_syscall_seq:
                                for bug_syscall in bug_syscall_seq.split(' '):
                                    if bug_syscall not in res_add_key_syscall:
                                        res_add_key_syscall.append(bug_syscall)        
        return res_add_key_syscall

    def __extract_dependent_syscalls(self, syscall, syzkaller_path, search_path="sys/linux", extension=".txt"):
        res = []
        dir = os.path.join(syzkaller_path, search_path)
        if not os.path.isdir(dir):
            self.logger.info("{} do not exist".format(dir))
            return res
        for file in os.listdir(dir):
            if file.endswith(extension):
                find_it = False
                f = open(os.path.join(dir, file), "r")
                text = f.readlines()
                f.close()
                line_index = 0
                for line in text:
                    if line.find(syscall) != -1:
                        find_it = True
                        break
                    line_index += 1

                if find_it:
                    upper_bound = 0
                    lower_bound = 0

                    for i in range(0, len(text)):

                        if line_index+i<len(text):
                            line = text[line_index+i]
                            if utilities.regx_match(r'^\n', line):
                                upper_bound = 1
                            if upper_bound == 0:
                                m = re.match(r'(\w+(\$\w+)?)\(', line)
                                if m != None and len(m.groups()) > 0:
                                    call = m.groups()[0]
                                    res.append(call)
                        else:
                            upper_bound = 1

                        if line_index-i>=0:
                            line = text[line_index-i]
                            if utilities.regx_match(r'^\n', line):
                                lower_bound = 1
                            if lower_bound == 0:
                                m = re.match(r'(\w+(\$\w+)?)\(', line)
                                if m != None and len(m.groups()) > 0:
                                    call = m.groups()[0]
                                    res.append(call)
                        else:
                            lower_bound = 1

                        if upper_bound and lower_bound:
                            return res
        return res
    

    def __save_error(self, hash_val):
        self.logger.info("case {} encounter an error. See log for details.".format(hash_val))
        self.__move_to_error()

    def __copy_crashes(self):
        crash_path = "{}/workdir/crashes".format(self.syzkaller_path)
        dest_path = "{}/crashes".format(self.current_case_path)
        i = 0
        if os.path.isdir(crash_path) and len(os.listdir(crash_path)) > 0:
            while(1):
                try:
                    shutil.copytree(crash_path, dest_path)
                    self.logger.info("Found crashes, copy them to {}".format(dest_path))
                    self.case_info_logger.info("Found crashes, copy them to {}".format(dest_path))
                    break
                except FileExistsError:
                    dest_path = "{}/crashes-{}".format(self.current_case_path, i)
                    i += 1

    def __move_to_analyzing(self):
        self.logger.info("Copy to analyzing")
        src = self.current_case_path
        base = os.path.basename(src)
        analyzing = "{}/work/analyzing".format(self.project_path)
        des = "{}/{}".format(analyzing, base)
        if not os.path.isdir(analyzing):
            os.makedirs(analyzing, exist_ok=True)
        if src == des:
            return
        if os.path.isdir(des):
            try:
                os.rmdir(des)
            except:
                self.logger.info("Fail to delete directory {}".format(des))
        shutil.move(src, des)
        self.current_case_path = des

    def remove_case_linux_kernel(self):
        case_hash = os.path.basename(self.current_case_path)
        if os.path.exists(self.current_case_path+'/.stamp/BUILD_SYZKALLER'):
            os.remove(self.current_case_path+'/.stamp/BUILD_SYZKALLER')
        if os.path.exists(self.current_case_path+'/.stamp/FINISH_FUZZING'):
            os.remove(self.current_case_path+'/.stamp/FINISH_FUZZING')
        if os.path.exists(self.current_case_path+'/.stamp/BUILD_KERNEL'):
            os.remove(self.current_case_path+'/.stamp/BUILD_KERNEL')
        if os.path.exists('{}/linux-{}'.format(self.save_linux_folder,case_hash)):
            shutil.rmtree('{}/linux-{}'.format(self.save_linux_folder,case_hash))
        if os.path.exists(self.current_case_path+'/gopath'):
            shutil.rmtree(self.current_case_path+'/gopath')


    def __move_to_warning_cases(self):
        self.logger.info("Copy to warning cases")
        src = self.current_case_path
        base = os.path.basename(src)
        warning_dir = "{}/work/warning".format(self.project_path)
        des = "{}/{}".format(warning_dir, base)
        if not os.path.isdir(warning_dir):
            os.makedirs(warning_dir, exist_ok=True)
        if src == des:
            return
        if os.path.isdir(des):
            try:
                os.rmdir(des)
            except:
                self.logger.info("Fail to delete directory {}".format(des))
        shutil.move(src, des)
        self.current_case_path = des

    def __move_to_completed(self):
        self.logger.info("Copy to completed")
        src = self.current_case_path
        base = os.path.basename(src)
        completed = "{}/work/completed".format(self.project_path)
        des = "{}/{}".format(completed, base)
        if not os.path.isdir(completed):
            os.makedirs(completed, exist_ok=True)
        if src == des:
            return
        if os.path.isdir(des):
            try:
                os.rmdir(des)
            except:
                self.logger.info("Fail to delete directory {}".format(des))
        shutil.move(src, des)
        self.current_case_path = des
    
    def __move_to_succeed(self, new_impact_type):
        self.logger.info("Copy to succeed")
        src = self.current_case_path
        base = os.path.basename(src)
        succeed = "{}/work/succeed".format(self.project_path)
        des = "{}/{}".format(succeed, base)
        if not os.path.isdir(succeed):
            os.makedirs(succeed, exist_ok=True)
        if src == des:
            return
        if os.path.isdir(des):
            try:
                os.rmdir(des)
            except:
                self.logger.info("Fail to delete directory {}".format(des))
        shutil.move(src, des)
        self.current_case_path = des
    
    def __move_to_error(self):
        self.logger.info("Copy to error")
        src = self.current_case_path
        base = os.path.basename(src)
        error = "{}/work/error".format(self.project_path)
        des = "{}/{}".format(error, base)
        if not os.path.isdir(error):
            os.makedirs(error, exist_ok=True)
        if src == des:
            return
        if os.path.isdir(des):
            os.rmdir(des)
        shutil.move(src, des)
        self.current_case_path = des
        self.remove_case_linux_kernel()

    def __create_dir_for_case(self):
        res, succeed = self.__copy_from_duplicated_cases()
        if res:
            return succeed
        path = "{}/.stamp".format(self.current_case_path)
        if not os.path.isdir(path):
            os.makedirs(path, exist_ok=True)
        return succeed

    def __copy_from_duplicated_cases(self):
        des = self.current_case_path
        base = os.path.basename(des)
        for dirs in ["completed", "incomplete", "error", "succeed", "analyzing", "warning"]:
            src = "{}/work/{}/{}".format(self.project_path, dirs, base)
            if src == des:
                continue
            if os.path.isdir(src):
                try:
                    shutil.move(src, des)
                    self.logger.info("Found duplicated case in {}".format(src))
                    return True, dirs == "succeed"
                except:
                    self.logger.info("Fail to copy the duplicated case from {}".format(src))
        return False, False
    
    def __get_default_log_format(self):
        return logging.Formatter('%(asctime)s %(levelname)s [{}] %(message)s'.format(self.index))

    def __init_case_logger(self, logger_name):
        
        handler = logging.FileHandler("{}/log".format(self.current_case_path))
        format = logging.Formatter('%(asctime)s [{}] %(message)s'.format(self.index))
        handler.setFormatter(format)
        logger = logging.getLogger(logger_name)
        logger.setLevel(self.logger.level)
        logger.addHandler(handler)
        logger.propagate = False
        if self.debug:
            logger.propagate = True
        return logger
    
    def __init_case_info_logger(self, logger_name):
        handler = logging.FileHandler("{}/info".format(self.current_case_path))
        format = self.__get_default_log_format()
        handler.setFormatter(format)
        logger = logging.getLogger(logger_name)
        logger.setLevel(self.logger.level)
        logger.addHandler(handler)
        logger.propagate = False
        if self.debug:
            logger.propagate = True
        return logger

    def __log_subprocess_output(self, pipe, log_level):
        for line in iter(pipe.readline, b''):
            if log_level == logging.INFO:
                self.case_logger.info(line)
            if log_level == logging.DEBUG:
                self.case_logger.debug(line)

        return False
