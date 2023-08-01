from typing import Type, Any

import frida
from pydantic import BaseModel, Field
from langchain.tools import ShellTool
from work.tools.frida.base import FridaBaseTool


class frida_ps(FridaBaseTool):
    name = "frida_ps"
    description = """使用frida的api来列出当前运行的进程，这个函数不需要传递参数"""
    args_schema: Type[BaseModel] = None

    def _run(self, *args: Any, **kwargs: Any):
        return ShellTool().run(tool_input={"commands": ["frida-ps -U"]}, start_color="blue")

    def _arun(self, *args: Any, **kwargs: Any):
        raise NotImplementedError("frida_ps does not support async")


class frida_spawn_input(BaseModel):
    """Inputs for frida_spawn"""
    package_name: str = Field(description="frida spawn 启动时候需要一个包名")


class frida_spawn(FridaBaseTool):
    name = "frida_spawn"
    description = """使用frida的api,通过spawn的方式来启动一个进程"""
    args_schema: Type[BaseModel] = frida_spawn_input

    def _run(self, package_name: str):
        cmd = "frida -U -f " + package_name
        pack_cmd = "cmd /C " + cmd
        response = ShellTool().run(tool_input={"commands": [pack_cmd]}, start_color="blue")
        return response

    def _arun(self, ticker: str):
        raise NotImplementedError("frida_spawn does not support async")


class frida_attach_input(BaseModel):
    """Inputs for frida_attach"""
    package_name: str = Field(description="附加时需要一个包名或者是应用名，可能是中文文本也可能是com.开头的包名")


class frida_attach(FridaBaseTool):
    name = "frida_attach"
    description = """使用frida的api来附加一个应用"""
    args_schema: Type[BaseModel] = frida_attach_input

    def _run(self, package_name: str, *args: Any, **kwargs: Any):
        self.devices = frida.get_usb_device()
        self.session = self.devices.attach(package_name)
        return self.session

    def _arun(self, ticker: str):
        raise NotImplementedError("frida_attach does not support async")


class frida_findBaseAddress_input(BaseModel):
    """Inputs for frida_findBaseAddress"""
    module_name: str = Field(description="使用frida去获取一个基地址的时候需要传递一个模块名")


class frida_findBaseAddress(FridaBaseTool):
    name = "frida_findBaseAddress"
    description = """使用frida的获取某一个库的基地址，需要一个模块名作为参数"""
    args_schema: Type[BaseModel] = frida_findBaseAddress_input

    def _run(self, module_name: str):
        devices = frida.get_usb_device()
        session = devices.attach(self.current_pkg_name)
        script = """
        rpc.exports = {
            frida_findBaseAddress: function (module_name, offset=0, length=0x60) {
                return Module.findBaseAddress(module_name)
            }
        };
        """
        script = session.create_script(script)
        script.on('message', self.on_message)
        script.load()
        return script.exports_sync.frida_findBaseAddress(module_name)

    def _arun(self, ticker: str):
        raise NotImplementedError("frida_findBaseAddress does not support async")


class frida_load_js_code_input(BaseModel):
    """Inputs for frida_load_js_code"""
    js_code: str = Field(description="需要加载的js文本内容，这个参数类型是string")


class frida_load_js_code(FridaBaseTool):
    name = "frida_load_js_code"
    description = """使用frida的api来加载一个js脚本，加载脚本前得先附加上应用，这里的入脚本可以是我们自己生成的也可以是自己写的"""
    args_schema: Type[BaseModel] = frida_load_js_code_input

    def _run(self, js_code: str, *args: Any, **kwargs: Any):
        self.devices = frida.get_usb_device()
        self.session = self.devices.attach(self.current_pkg_name)
        self.script = self.session.create_script(js_code)
        self.script.on('message', self.on_message)
        return self.script.load()

    def _arun(self, js_code: str):
        raise NotImplementedError("frida_spawn does not support async")


class frida_exec_js_code_method_input(BaseModel):
    """Inputs for frida_load_js_code"""
    method_name: str = Field(description="在加载脚本后需要调用的函数名")
    method_args: list = Field(description="调用函数的参数,可有可无")


class frida_exec_js_code_method(FridaBaseTool):
    name = "frida_exec_js_code_method"
    description = """使用frida的api来执行一个依旧注入的脚本里面的方法，需要先注入js脚本才可以调用这个方法"""
    args_schema: Type[BaseModel] = frida_exec_js_code_method_input

    def _run(self, method_name, method_args, *args: Any, **kwargs: Any):
        return self.script.exports_sync[method_name](method_args)

    def _arun(self, ticker: str):
        raise NotImplementedError("frida_spawn does not support async")
