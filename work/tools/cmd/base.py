from typing import Any, Type

from pydantic import BaseModel

from langchain.tools import BaseTool, ShellTool


class get_top_activity_info(BaseTool):

    name = "get_top_activity_info"
    description = """获取当前手机的顶层activity信息"""
    args_schema: Type[BaseModel] = None

    cmd = "adb shell \"dumpsys activity activities\""

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        return ShellTool().run(tool_input={"commands": [self.cmd]}, start_color="blue")

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        pass


class get_top_package_name(BaseTool):

    name = "get_top_package_name"
    description = """获取当前手机的顶层包名"""
    args_schema: Type[BaseModel] = None

    cmd = "adb shell \"dumpsys activity activities | " \
          "grep 'mResumedActivity' | awk '{print $4}' | awk -F '/' '{print $1}'\""

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        return ShellTool().run(tool_input={"commands": [self.cmd]}, start_color="blue")

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        return ShellTool().arun(tool_input={"commands": [self.cmd]}, start_color="blue")


if __name__ == '__main__':
    # test ↓
    ret = get_top_activity_info().run(tool_input={})
    print(ret)