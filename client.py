import socket
from threading import Thread
from tkinter import messagebox


class Client:
    def __init__(self):
        self.HOST = "localhost"
        self.PORT = 12345
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.HOST, self.PORT))
        self.receive_thread = Thread(target=self.receive_message, daemon=True)
        self.receive_thread.start()
        self.send_thread = None

    def client_close(self):
        self.client_socket.close()

    def send(self, message):
        self.send_thread = Thread(target=self.send_message, daemon=True, args=(message,))
        self.send_thread.start()

    def receive_message(self):
        while True:
            try:
                message = self.client_socket.recv(1024).decode('utf-8')
                if message == "":
                    continue
                else:
                    print(message)
                # messagebox.showinfo("接收", f"加密端消息:{message}")
            except OSError:
                break

    def send_message(self, message):
        self.client_socket.send(bytes(message, 'utf-8'))
        messagebox.showinfo("成功", "发送成功")
