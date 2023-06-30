import frida


class base_py_frida:

    def __init__(self):
        self.devices = None
        self.session = None
        self.script = None

    def attach(self, process_name):
        try:
            self.devices = frida.get_usb_device()
            if not self.devices:
                return "USB device found."
            self.session = self.devices.attach(process_name)
        except frida.ProcessNotFoundError:
            return f"Process '{process_name}' not found."

    def detach(self):
        if self.session:
            self.session.detach()
            return "Detached from the process."
        else:
            return "No process attached."

    def on_message(self, message, data):
        # self.message_queue.put(message)
        if message['type'] == 'send1':
            print("[*] {}".format(message['payload']))
        elif message['type'] == 'error':
            print("[ERROR] {}".format(message['description']))
        # else:
        #     if data is not None:
        #         print("[*] Message: {}, Data: {}".format(message, data.hex()))
        #     else:
        #         print("[*] Message: {}, No Data".format(message))

    def load_js(self, script):
        self.devices = frida.get_usb_device()
        self.session = self.devices.attach("金属小分队")
        self.script = self.session.create_script(script)
        self.script.on('message', self.on_message)
        self.script.load()
        return "Script loaded."

    def exec(self, method, *args):
        return self.script.exports[method](*args)
