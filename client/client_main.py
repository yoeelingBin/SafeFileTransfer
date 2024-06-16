import tkinter as tk
import threading
from client_view import DownloadFrame, UploadFrame, AboutFrame
from client import Client
from tkinter import Menu

class MainPage:
    '''
    Description: 客户端上传主页
    '''
    def __init__(self, master=None, client=None):
        self.root = master
        self.root.title("安全文件传输客户端")
        self.root.geometry("780x400")
        self.client = client
        self.createPage()

        # 连接交换密钥
        # self.client.connect()

    def createPage(self):
        '''
        Usage: 创建页面
        '''
        self.downloadPage = DownloadFrame(self.root, self.client)  # 创建不同Frame
        self.uploadPage = UploadFrame(self.root, self.client)
        self.aboutPage = AboutFrame(self.root, self.client)
        self.downloadPage.pack()  # 默认显示数据录入界面
        menubar = Menu(self.root)
        menubar.add_command(label='文件列表', command=self.downloadData)
        menubar.add_command(label='上传文件', command=self.uploadData)
        menubar.add_command(label='关于', command=self.aboutDisp)
        self.root['menu'] = menubar  # 设置菜单栏
        self.root.resizable(0, 0)  # 阻止窗口变化

    def updateList(self):
        '''
        Usage: 查看文件列表
        '''
        file_list = self.client.list_files()
        self.downloadPage.dealline(file_list)

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

if __name__ == "__main__":
    root = tk.Tk()
    app = MainPage(root)
    root.mainloop()
