from abc import ABC
from dataclasses import Field
from typing import Any, Optional

import frida

from langchain.tools import BaseTool


class FridaBaseTool(BaseTool, ABC):

    current_pkg_name: Optional[str] = None
    devices: Optional[frida.core.Device] = None
    session: Optional[frida.core.Session] = None
    script: Optional[frida.core.Script] = None

    def __init__(self, **data: Any):
        super().__init__(**data)

    @staticmethod
    def on_message(message, data):
        if message['type'] == 'send':
            return message['payload']
        elif message['type'] == 'error':
            return message['description']

    def frida_attach(self, process_name):
        try:
            self.devices = frida.get_usb_device()
            if not self.devices:
                return "USB device found."
            self.session = self.devices.attach(process_name)
        except frida.ProcessNotFoundError:
            return f"Process '{process_name}' not found."
