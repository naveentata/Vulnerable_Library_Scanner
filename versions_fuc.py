import ast
import subprocess
from inspect import getmembers, isfunction
import re
from packaging.version import parse as parse_version
from urllib.request import urlopen
import json
import requests
import yaml
import os, glob


all_fun = []
class ParseCall(ast.NodeVisitor):
    def __init__(self):
        self.ls = []
    def visit_Attribute(self, node):
        ast.NodeVisitor.generic_visit(self, node)
        self.ls.append(node.attr)
    def visit_Name(self, node):
        self.ls.append(node.id)


class FindFuncs(ast.NodeVisitor):
    def visit_Call(self, node):
        p = ParseCall()
        p.visit(node.func)
        all_fun.append(".".join(p.ls))
        # print (".".join(p.ls))
        ast.NodeVisitor.generic_visit(self, node)


path = '.'
for filename in glob.glob(os.path.join(path, '*.py')):
   with open(os.path.join(os.getcwd(), filename), 'r') as f: # open in readonly mode
    print(filename)
    codes = f.readlines()
    codes = "".join(codes)
    tree = ast.parse(codes)
    FindFuncs().visit(tree)

def get_cve(input, ver_map):
    library = {}
    for library_name in input: 
        url = "https://api.cvesearch.com/search?q="+str(library_name)
        response = requests.get(url)
        print(url)
        print(response)
        data_json = response.json()
        cve_data = {}

        data_json = data_json["response"]
        for cve in data_json: 
            cve_data[cve] = data_json[str(cve)]["basic"]["description"]

        for function_name in input[library_name]:
            for cve, description in cve_data.items():

                if function_name in description: 
                    version_affected_before = "N/A"

                    if "versionEndExcluding" in data_json[str(cve)]["threat_intel"]["general"]["configurations"]["nodes"][0]["cpe_match"][0]:
                        version_affected_before = data_json[str(cve)]["threat_intel"]["general"]["configurations"]["nodes"][0]["cpe_match"][0]["versionEndExcluding"]

                    if version_affected_before == "N/A":
                        res = re.search(r"\d+(\.\d+)+", description)
                        ver = res.group(0)
                        version_affected_before = ver

                    cvssV3_score = data_json[str(cve)]["details"]["cvssV3_score"]

                    if library_name in library : 

                        library[library_name].append({"function_name": function_name, "cve": cve, "cvssV3_score" : cvssV3_score, "description": description, "Versions affected before": version_affected_before, "version_installed": ver_map[library_name][0], "version_latest": ver_map[library_name][1], "upgrade_required": "Yes" if parse_version(ver_map[library_name][0]) < parse_version(version_affected_before) else "No"})
                    else: 
                        library[library_name] = [{"function_name": function_name, "cve": cve, "cvssV3_score" : cvssV3_score, "description": description, "Versions affected before": version_affected_before, "version_installed": ver_map[library_name][0], "version_latest": ver_map[library_name][1], "upgrade_required": "Yes" if parse_version(ver_map[library_name][0]) < parse_version(version_affected_before) else "No"}]
                    
                    # print("function_name: ",function_name, "\n library_name:  ",library_name, "\n cve: ", cve, "\n description: ", description, "\n Versions affected before: ", version_affected_before,"\n cvssV3_score: ", cvssV3_score, "\n")
        
        print(library)
        with open('data1.json', 'w', encoding='utf-8') as f:
            json.dump(library, f, ensure_ascii=False, indent=4)


def scan_functions(file_path):
    with open(file_path) as f:
        codes = f.readlines()
        codes = "".join(codes)
        tree = ast.parse(codes)
        FindFuncs().visit(tree)
    # return all_fun

# f = open('test3.py')
# codes = f.readlines()
# codes = "".join(codes)
# # tree = ast.parse(f.read())
# tree = ast.parse(codes)
# FindFuncs().visit(tree)
# scan_functions("test3.py")
print(all_fun)
a = subprocess.check_output(["pip-check", "--cmd=pip3", "--hide-unchanged", "-a"])


a = a.decode("utf-8")

a = a.split("\n")
ver_map = {}

for i in a:
    s = i.split("|")
    if len(s) > 1 and s[1] != " " and "." in s[2].strip():
        ver_map[s[1].strip()] = [s[2].strip(), s[3].strip()]
print(ver_map)
print(len(ver_map))

print([a[0] for a in getmembers(ast) if isfunction(a[1])])
dir_lib_map = {}

prev = set()
modules = {}
for x in ver_map:
    try:
        if x == 'setuptools':
            print(x)
            continue
        if x == "PyYAML":
            print("*******")
            modules[x] = dir(yaml)
            continue
        x = x.replace("-", "_")
        exec("from {module} import *".format(module=x))

        curr = set(dir()) - prev
        prev = set(dir())
        modules[x] = curr
        print ("Successfully imported ", x, '.')
    except ImportError:
        print("Error importing ", x, '.')
        pass
print(modules)

# for i in modules:
#     print(i)
#     print(modules[i])

dir_lib_map = {}

for i in all_fun:
    for j in modules:
        if i.split(".")[-1] in modules[j]:
            dir_lib_map[i.split(".")[-1]] = j

print(dir_lib_map)


invert = {}

for i in dir_lib_map:
    if dir_lib_map[i] not in invert:
        invert[dir_lib_map[i]] = []
    invert[dir_lib_map[i]].append(i)
print(invert)

string = "The numpy.pad function in Numpy 1.13.1 and older versions is missing input validation. An empty list or ndarray will stick into an infinite loop, which can allow attackers to cause a DoS attack."
res = re.search(r"\d+(\.\d+)+", string)

ver = res.group(0)
print(ver)
ver2 = '1.16.1'
if parse_version(ver) < parse_version(ver2):
    print("yes")

{'numpy': ['array', 'pad'], 'urlib':['urlopen']}

get_cve(invert, ver_map)
