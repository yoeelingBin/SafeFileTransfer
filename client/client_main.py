import tkinter as tk
import threading
from client_view import DownloadFrame, UploadFrame, AboutFrame
from client import Client
from tkinter import Menu

class MainPage:
    '''
    Description: 客户端上传主页
    '''
    def __init__(self, master=None):
        self.root = master
        self.root.title("文件上传客户端")
        self.root.geometry("780x400")
        self.client = Client()
        self.createPage()

        # self.upload_button = tk.Button(master, text="选择文件上传", command=self.upload_file)
        # self.upload_button.pack(pady=20)

        # self.status_label = tk.Label(master, text="", fg="blue")
        # self.status_label.pack(pady=20)

    def createPage(self):
        '''
        Usage: 创建页面
        '''
        self.downloadPage = DownloadFrame(self.root, self.client)  # 创建不同Frame
        self.uploadPage = UploadFrame(self.root, self.client)
        self.aboutPage = AboutFrame(self.root, self.client)
        self.uploadPage.pack()  # 默认显示数据录入界面
        menubar = Menu(self.root)
        menubar.add_command(label='文件列表', command=self.downloadData)
        menubar.add_command(label='上传文件', command=self.uploadData)
        menubar.add_command(label='关于', command=self.aboutDisp)
        self.root['menu'] = menubar  # 设置菜单栏
        self.root.resizable(0, 0)  # 阻止窗口变化

    def updateList(self):
        '''
        Usage: 更新文件列表
        '''
        self.client.update()
        self.downloadPage.dealline()

    def downloadData(self):
        '''
        Usage: 下载数据
        '''
        # 开启线程更新列表
        thread = threading.Thread(target=self.updateList,)
        thread.start()

        self.downloadPage.pack()
        self.uploadPage.pack_forget()
        self.aboutPage.pack_forget()

    def uploadData(self):
        '''
        Usage: 上传数据
        '''
        self.downloadPage.pack_forget()
        self.uploadPage.pack()
        self.aboutPage.pack_forget()


    def aboutDisp(self):
        '''
        Usage: 显示关于
        '''
        self.downloadPage.pack_forget()
        self.uploadPage.pack_forget()
        self.aboutPage.pack()

    # def upload_file(self):
    #     '''
    #     Usage: 上传文件
    #     '''
    #     file_path = filedialog.askopenfilename()
    #     if file_path:
    #         self.status_label.config(text="正在上传...")
    #         try:
    #             self.client.upload_file(file_path)
    #             self.status_label.config(text="上传成功！")
    #         except Exception as e:
    #             messagebox.showerror("错误", f"上传失败: {e}")
    #             self.status_label.config(text="上传失败")

if __name__ == "__main__":
    root = tk.Tk()
    app = MainPage(root)
    root.mainloop()