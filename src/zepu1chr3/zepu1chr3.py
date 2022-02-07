#!/usr/bin/python3

import json
try:
    import r2pipe
except:
    print("Error: >r2pipe< module not found!")

class Binary:
    def __init__(self):
        pass
    def File(self, target_file):
        '''
            Desctiption: This method is for specifying target binary files
            Return value: A handler for target binary file
            Usage:
                zep = zepu1chr3.Binary()
                target = zep.File("WannaCry.exe")
        '''
        self.target_file = target_file
        if self.target_file is None or self.target_file == "" or self.target_file == " ":
            return None
        else:
            fhandler = r2pipe.open(self.target_file)
            fhandler.cmd("aaa") # Running tests on file
            return fhandler
    def GetSymbols(self, file_handler):
        '''
            Description: This method is for getting symbols from binary files
            Return value:
                symbols => An array of symbols
                [
                    {
                        "name": "sym.imp.kernel32.dll_GetModuleHandleA", 
                        "offset": "0x7160d4"
                    }...
                ]
            Usage:
                zep = zepu1chr3.Binary()
                target = zep.File("WannaCry.exe")
                symbols = zep.GetSymbols(target)
        '''
        self.file_handler = file_handler
        if str(type(self.file_handler)) == "<class 'r2pipe.open_sync.open'>":
            symbols = []
            syms = json.loads(self.file_handler.cmd("fs symbols; fj"))
            for sym in syms:
                symbols.append({"name": sym["name"], "offset": hex(sym["offset"])})
            return symbols
        else:
            return None
    def GetImports(self, file_handler):
        '''
            Description: This method is for getting imports from binary files
            Return value:
                imports => An array of imports
                [
                    {
                        "name": "sym.imp.shell32.dll_ShellExecuteA", 
                        "realname": "ShellExecuteA", 
                        "offset": "0x716108"
                    }...
                ]
            Usage:
                zep = zepu1chr3.Binary()
                target = zep.File("WannaCry.exe")
                imports = zep.GetImports(target)
        '''
        self.file_handler = file_handler
        if str(type(self.file_handler)) == "<class 'r2pipe.open_sync.open'>":
            imports = []
            imps = json.loads(self.file_handler.cmd("fs imports; fj"))
            for im in imps:
                imports.append({"name": im["name"], "realname": im["realname"], "offset": hex(im["offset"])})
            return imports
        else:
            return None
    def GetSections(self, file_handler):
        '''
            Description: This method is for getting section informations from binary files
            Return value:
                sections => An array of sections
                [
                    {
                        "name": "section.sect_0",
                        "size": 40960,
                        "offset": "0x4123b2"
                    }...
                ]
            Usage:
                zep = zepu1chr3.Binary()
                target = zep.File("WannaCry.exe")
                sections = zep.GetSections(target)
        '''
        self.file_handler = file_handler
        if str(type(self.file_handler)) == "<class 'r2pipe.open_sync.open'>":
            sections = []
            sects = json.loads(self.file_handler.cmd("fs sections; fj"))
            for sec in sects:
                sections.append({"name": sec["name"], "size": sec["size"], "offset": hex(sec["offset"])})
            return sections
        else:
            return None
    def GetFunctions(self, file_handler):
        '''
            Description: This method is for getting functions from binary file
            Return value:
                functions => An array of functions
                [
                    {
                        "name": "fcn.0040368a",
                        "size": 40960,
                        "offset": "0x1bc12d",
                        "xrefs: [{'addr': 268509156, 'type': 'CALL'}]
                    }...
                ]
            Usage:
                zep = zepu1chr3.Binary()
                target = zep.File("WannaCry.exe")
                functions = zep.GetFunctions(target)
        '''
        self.file_handler = file_handler
        if str(type(self.file_handler)) == "<class 'r2pipe.open_sync.open'>":
            functions = []
            funcs = json.loads(self.file_handler.cmd("fs functions; fj"))
            for ff in funcs:
                functions.append({"name": ff["name"], "size": ff["size"], "offset": hex(ff["offset"])})
            return functions
        else:
            return None
    def DisassembleFunction(self, file_handler, given_function, only_codes):
        '''
            Descriptions: This method disasembles given offset or function with r2 style!!
            Return value: Values about disassembled function
            Usage:
                zep = zepu1chr3.Binary()
                target = zep.File("WannaCry.exe")
                section = zep.GetSections(target)
                disas = zep.DisassembleFunction(target, section[0]['name'], only_codes=False)
                    OR
                disas = zep.DisassembleFunction(target, section[0]['offset'], only_codes=False)
            Notes: If you specify "only_codes=True" you can get only assembly code and offsets
        '''
        self.file_handler = file_handler
        self.given_function = given_function
        self.only_codes = only_codes
        if str(type(self.file_handler)) == "<class 'r2pipe.open_sync.open'>" and str(type(self.given_function)) == "<class 'str'>" and str(type(self.only_codes)) == "<class 'bool'>":
            disass = json.loads(self.file_handler.cmd(f"s {self.given_function}; pdfj"))
            if self.only_codes:
                codes = []
                for cc in disass["ops"]:
                    if "xrefs" in cc.keys():
                        codes.append({"offset": hex(cc["offset"]), "code": cc["disasm"], "xrefs": cc["xrefs"]})
                    else:
                        codes.append({"offset": hex(cc["offset"]), "code": cc["disasm"], "xrefs": []})
                return codes
            else:
                return disass
        return None