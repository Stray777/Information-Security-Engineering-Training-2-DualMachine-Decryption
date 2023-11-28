import tkinter as tk
from tkinter import messagebox
from tkinter import ttk


class View:
    def __init__(self):
        self.root = tk.Tk()
        # 主界面标题
        self.root.title("加解密实践-解密端")
        # 设置窗口大小和居中
        self.screen_width = self.root.winfo_screenwidth()
        self.screen_height = self.root.winfo_screenheight()
        self.root.geometry(f"500x600+{(self.screen_width - 500) // 2}+{(self.screen_height - 600) // 2}")

        # 创建容器
        self.frame2 = tk.Frame(self.root, bd=2, relief=tk.GROOVE, padx=15, pady=15)
        self.frame2.pack(pady=30)

        # 容器2
        self.label_decrypt = tk.Label(self.frame2, text="解密", font=("Helvetica", 20, "bold"))
        self.label_decrypt.grid(row=0, column=0)
        self.label_ciphertext = tk.Label(self.frame2, text="Ciphertext")
        self.label_ciphertext.grid(row=1, column=0)
        self.text_ciphertext = tk.Text(self.frame2, height=10, width=30)
        self.text_ciphertext.grid(row=1, column=1)
        self.label_file2 = tk.Label(self.frame2, text="File")
        self.label_file2.grid(row=2, column=0)
        self.button_file2 = tk.Button(self.frame2, text="Select File")
        self.button_file2.grid(row=2, column=1, pady=10)
        self.label_key2 = tk.Label(self.frame2, text="KEY")
        self.label_key2.grid(row=3, column=0)
        self.entry_key2 = tk.Entry(self.frame2)
        self.entry_key2.grid(row=3, column=1)
        self.label_decrypt_algorithm = tk.Label(self.frame2, text="Decrypt algorithm")
        self.label_decrypt_algorithm.grid(row=4, column=0, pady=10)
        self.decrypt_options = ["CaesarCipher", "KeywordCipher", "RSA", "PlayfairCipher"]
        self.combobox_algorithm2 = ttk.Combobox(self.frame2, values=self.decrypt_options, state="readonly")
        self.combobox_algorithm2.bind("<<ComboboxSelected>>", self.decrypt_options_tips)
        self.combobox_algorithm2.set("Select an algorithm")
        self.combobox_algorithm2.grid(row=4, column=1)
        self.button_decrypt = tk.Button(self.frame2, text="Decrypt")
        self.button_decrypt.grid(row=6, column=1, sticky='w')
        self.button_sharekey = tk.Button(self.frame2, text="Share")
        self.button_sharekey.grid(row=3, column=2)
        self.label_plaintext = tk.Label(self.frame2, text="Plaintext")
        self.label_plaintext.grid(row=5, column=0)
        self.text_plaintext = tk.Text(self.frame2, height=10, width=30)
        self.text_plaintext.grid(row=5, column=1, pady=5)
        self.button_send = tk.Button(self.frame2, text="Send")
        self.button_send.grid(row=6, column=1, sticky='e', pady=5)

    def set_button_send(self, command):
        self.button_send.configure(command=command)

    def set_button_sharekey(self, command):
        self.button_sharekey.configure(command=command)

    def set_button_decrypt(self, command):
        self.button_decrypt.configure(command=command)

    def set_button_file2(self, command):
        self.button_file2.configure(command=lambda: command(2))

    def pop_up_window(self, title='', label_text='', content='', button_text='') -> None:
        """弹窗"""
        # 弹窗主窗口
        toplevel = tk.Toplevel(self.root)
        toplevel.title(title)
        toplevel.geometry(f"400x250+{(self.screen_width - 400) // 2}+{(self.screen_height - 250) // 2}")

        # 组件
        label = tk.Label(toplevel, text=label_text)
        label.pack(pady='5')
        text = tk.Text(toplevel, height=10, width=30)
        text.delete(1.0, tk.END)
        text.insert(tk.END, content)
        text.pack()
        button = tk.Button(toplevel, text=button_text, command=toplevel.destroy)
        button.pack(pady='5')

    def decrypt_options_tips(self, _=None):
        selected_item = self.combobox_algorithm2.get()
        if selected_item == "RSA":
            messagebox.showinfo("RSA提醒", "每个值需要以分号( ; )隔开\nkey_d;key_n\n如: 233;437")
