import socket
from threading import Thread
import tkinter as tk


class Client:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Socket通信")

        self.message_listbox = tk.Listbox(self.root, height=15, width=50, bg="lightgray")
        self.message_listbox.pack(padx=10, pady=10)

        self.my_message = tk.StringVar()
        self.entry_field = tk.Entry(self.root, textvariable=self.my_message)
        self.entry_field.bind("<Return>", self.send_message)
        self.entry_field.pack(padx=10, pady=10)

        self.send_button = tk.Button(self.root, text="发送", command=self.send_message)
        self.send_button.pack(padx=10, pady=10)

        self.HOST = "localhost"
        self.PORT = 12345
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.HOST, self.PORT))

        self.receive_thread = Thread(target=self.receive_message)
        self.receive_thread.start()

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

    def receive_message(self):
        while True:
            try:
                message = self.client_socket.recv(1024).decode('utf-8')
                print(f"client message: {message}")
            except OSError:
                break

    def send_message(self):
        message = self.my_message.get()
        self.my_message.set("")
        self.client_socket.send(bytes(message, 'utf-8'))
        if message == "/exit":
            self.client_socket.close()
            self.root.quit()

    def on_closing(self, event=None):
        self.my_message.set("/exit")
        self.send_message()
