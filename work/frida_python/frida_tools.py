from typing import Type, Any

import frida
from pydantic import BaseModel, Field

from langchain.tools import BaseTool
from langchain.tools import PythonREPLTool, ShellTool
from work.frida_python.base_py_frida import base_py_frida

def on_message(message, data):
    if message['type'] == 'send1':
        print("[*] {}".format(message['payload']))
    elif message['type'] == 'error':
        print("[ERROR] {}".format(message['description']))


class FRIDA_PS(BaseTool):
    name = "frida_ps"
    description = """使用frida的api来列出当前运行的进程，这个函数不需要传递参数"""
    args_schema: Type[BaseModel] = None

    def _run(self, *args: Any, **kwargs: Any):
        return ShellTool().run(tool_input={"commands": ["frida-ps -U"]}, start_color="blue")

    def _arun(self, *args: Any, **kwargs: Any):
        raise NotImplementedError("frida_ps does not support async")


class FRIDA_SPAWN_INPUT(BaseModel):
    """Inputs for FRIDA_SPAWN"""
    package_name: str = Field(description="frida spawn 启动时候需要一个包名")


class FRIDA_SPAWN(BaseTool):
    name = "FRIDA_SPAWN"
    description = """使用frida的api来启动一个进程"""
    args_schema: Type[BaseModel] = FRIDA_SPAWN_INPUT

    def _run(self, package_name: str):
        cmd = "frida -U -f " + package_name
        # start cmd /k "frida-ps -U -f  com.gzcc.jsxfd.huawei"
        pack_cmd = "cmd /C " + cmd
        response = ShellTool().run(tool_input={"commands": [pack_cmd]}, start_color="blue")
        return response

    def _arun(self, ticker: str):
        raise NotImplementedError("FRIDA_SPAWN does not support async")


class FRIDA_GET_BASE_ADDRESS_INPUT(BaseModel):
    """Inputs for FRIDA_SPAWN"""
    module_name: str = Field(description="使用frida去获取一个基地址的时候需要传递一个模块名")


class FRIDA_GET_BASE_ADDRESS(BaseTool):
    name = "FRIDA_GET_BASE_ADDRESS"
    description = """使用frida的获取某一个库的基地址"""
    args_schema: Type[BaseModel] = FRIDA_GET_BASE_ADDRESS_INPUT

    def _run(self, module_name: str):
        devices = frida.get_usb_device()
        session = devices.attach("猜猜我谁")
        script = """
        rpc.exports = {
            testf: function (module_name, offset=0, length=0x60) {
                return Module.findBaseAddress(module_name)
            }
        };
        """
        script = session.create_script(script)
        script.on('message', on_message)
        script.load()
        return script.exports_sync.testf(module_name)

    def _arun(self, ticker: str):
        raise NotImplementedError("FRIDA_SPAWN does not support async")


