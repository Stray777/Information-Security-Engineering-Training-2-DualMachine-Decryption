import socket
from threading import Thread
from tkinter import messagebox


class Client:
    def __init__(self):
        self.HOST = "localhost"
        self.PORT = 12344
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.HOST, self.PORT))
        self.receive_thread = Thread(target=self.receive_message, daemon=True)
        self.receive_thread.start()
        self.send_thread = None

    def client_close(self):
        self.client_socket.close()

    def send(self, message, file_id):
        self.send_thread = Thread(target=self.send_message, daemon=True, args=(message, file_id))
        self.send_thread.start()

    def receive_message(self):
        while True:
            try:
                message1 = self.client_socket.recv(1024).decode('utf-8')
                message2 = self.client_socket.recv(1024).decode('utf-8')
                with open(message1, 'w') as file:
                    file.write(message2)
                messagebox.showinfo("接收", f"收到来自服务端的文件:{message1}")
            except OSError:
                break

    def send_message(self, message, file_id):
        if file_id == 1:
            self.client_socket.send(bytes("key.txt", 'utf-8'))
        elif file_id == 2:
            self.client_socket.send(bytes("plaintext.txt", 'utf-8'))
        self.client_socket.send(bytes(message, 'utf-8'))
        messagebox.showinfo("成功", "发送成功")
