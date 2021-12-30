#!/usr/bin/env python3
# -*- encoding: utf8 -*-

"""
shellcheck 工具
功能: shell脚本检查
用法: python3 shellcheck.py
本地调试步骤:
1. 添加环境变量: export SOURCE_DIR="xxx/src_dir"
2. 添加环境变量: export TASK_REQUEST="xxx/task_request.json"
3. 按需修改task_request.json文件中各字段的内容
4. 命令行cd到项目根目录,执行命令:  python3 shellcheck.py
"""
import os
import json
import subprocess
import platform


class CheckTool:
    """check tool"""

    def __get_task_params(self):  # pylint: disable=R0201
        """
        获取需要任务参数
        :return:
        """
        task_request_file = os.environ.get("TASK_REQUEST")
        with open(task_request_file, "r") as reqfile:
            task_request = json.load(reqfile)
        task_params = task_request["task_params"]
        return task_params

    # pylint: disable=R0201
    def __get_dir_files(self, root_dir, want_suffix=""):
        """
        在指定的目录下,递归获取符合后缀名要求的所有文件
        :param root_dir:
        :param want_suffix:
            str|tuple,文件后缀名.单个直接传,比如 ".py";
            多个以元组形式,比如 (".h", ".c", ".cpp")
            默认为空字符串,会匹配所有文件
        :return: list, 文件路径列表
        """
        files = set()
        for dirpath, _, filenames in os.walk(root_dir):
            for filename in filenames:
                if filename.lower().endswith(want_suffix):
                    fullpath = os.path.join(dirpath, filename)
                    files.add(fullpath)
        files = list(files)
        return files

    # pylint: disable=R0201
    def get_diff_files(self, diff_file_json):
        """get diff files"""
        # 需要扫描的文件后缀名
        want_suffix = ".sh"
        with open(diff_file_json, "r") as reqfile:
            diff_files = json.load(reqfile)
            scan_files = [path for path in diff_files if path.lower().endswith(want_suffix)]
        return scan_files

    # pylint: disable=R0201
    def get_scan_files(self,):
        """get scan files"""
        # 需要扫描的文件后缀名
        want_suffix = ".sh"
        # 代码目录直接从环境变量获取
        source_dir = os.environ.get("SOURCE_DIR", None)
        print("[debug] source_dir: %s" % source_dir)
        # 从 DIFF_FILES 环境变量中获取增量文件列表存放的文件(全量扫描时没有这个环境变量)
        diff_file_json = os.environ.get("DIFF_FILES")
        if diff_file_json:  # 如果存在 DIFF_FILES, 说明是增量扫描, 直接获取增量文件列表
            print("get diff file: %s" % diff_file_json)
            scan_files = self.get_diff_files(diff_file_json)
        else:  # 未获取到环境变量,即全量扫描,遍历source_dir获取需要扫描的文件列表
            scan_files = self.__get_dir_files(source_dir, want_suffix)
        return scan_files

    def run(self):
        """
        :return:
        """
        # 其他参数从task_request.json文件获取
        task_params = self.__get_task_params()
        # 环境变量
        envs = task_params["envs"]
        print("[debug] envs: %s" % envs)
        # 前置命令
        pre_cmd = task_params["pre_cmd"]
        print("[debug] pre_cmd: %s" % pre_cmd)
        # 编译命令
        build_cmd = task_params["build_cmd"]
        print("[debug] build_cmd: %s" % build_cmd)
        # 规则
        rules = task_params["rules"]
        # 查看path环境变量
        print("[debug] path: %s" % os.environ.get("PATH"))
        # 查看path环境变量
        print("[debug] 查看python version")
        subproc = subprocess.Popen(["python", "--version"])
        subproc.wait()
        # ------------------------------------------------------------------ #
        # 增量扫描时,可以通过环境变量获取到diff文件列表,只扫描diff文件,减少耗时
        # 此处获取到的diff文件列表,已经根据项目配置的过滤路径过滤
        # ------------------------------------------------------------------ #
        scan_files = self.get_scan_files()
        result = []
        if not scan_files:
            print("[debug] no files to scan")
            with open("result.json", "w") as resfp:
                json.dump(result, resfp, indent=2)
            return

        sysstr = platform.system()
        if sysstr == "Windows":
            print("Call Windows tasks")
            cmd = "./shellcheck-stable.exe -f json -s bash "
        elif sysstr == "Linux":
            print("Call Linux tasks")
            cmd = "./shellcheck -f json -s bash "
        else:
            print("Call Mac tasks")
            cmd = "./shellcheck_mac -f json -s bash "
        cmd += " ".join(scan_files)
        subproc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        outputs, _ = subproc.communicate()
        try:
            outputs_data = json.loads(outputs)
        except ValueError:
            print("[debug] cannot load shellcheck outputs: %s" % outputs)
            with open("result.json", "w") as resfp:
                json.dump(result, resfp, indent=2)
            return
        for output in outputs_data:
            res = {}
            res["path"] = output["file"]
            res["line"] = output["line"]
            res["column"] = output["column"]
            res["msg"] = output["message"]
            res["refs"] = []
            for rule in rules:
                if rule == "SC{0}".format(output["code"]):
                    res["rule"] = "SC{0}".format(output["code"])
                    result.append(res)

        # 输出结果到指定的json文件
        with open("result.json", "w") as resfp:
            json.dump(result, resfp, indent=2)


if __name__ == "__main__":
    print("-- start run tool ...")
    CheckTool().run()
    print("-- end ...")
