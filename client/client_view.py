from tkinter import *
from tkinter.messagebox import *
from tkinter import ttk
from tkinter import filedialog
import re
import threading

pattern = '{"文件名": "(.*?)", "上传者": "(.*?)", "上传时间": "(.*?)", "大小": "(.*?)"}'
patch = re.compile(pattern)

class DownloadFrame(Frame):  # 继承Frame类
    '''
    Description: 下载文件页面
    '''
    def __init__(self, master=None,client=None):
        Frame.__init__(self, master)
        self.root = master  # 定义内部变量root
        self.scrollbar = Scrollbar(self.root, )
        self.scrollbar.pack(side=RIGHT, fill=Y)
        self.client = client
        self.createPage()

    def createPage(self):
        '''
        Usage: 创建页面
        '''
        title = ['2', '3', '4', ]
        self.box = ttk.Treeview(self, columns=title,
                                yscrollcommand=self.scrollbar.set,
                                show='headings', height=15)

        self.box.column('2', width=300, anchor='center')
        self.box.column('3', width=150, anchor='center')
        self.box.column('4', width=150, anchor='center')

        self.box.heading('2', text='文件名')
        self.box.heading('3', text='上传时间')
        self.box.heading('4', text='大小')

        self.dealline(self.client.list_files())

        self.scrollbar.config(command=self.box.yview)
        self.box.pack()

        Label(self, text=" ", fg='red').pack()
        Button(self, text=' 下载 ',command=self.download).pack(expand=1, fill="both", side="left", anchor="w")
        Button(self, text=' 退出 ', command=self.isquit).pack(expand=1, fill="both", side="left", anchor="w")


    # 这里的实现方式是从log文件中读出文件的大小和上传时间等信息
    # def readdata(self, ):
    #     """逐行读取文件"""

    #     # 读取gbk编码文件，需要加encoding='utf-8'
    #     f = open('./ClientCache/result.txt', 'r', encoding='utf-8')
    #     line = f.readline()
    #     while line:
    #         yield line
    #         line = f.readline()
    #     f.close()

    def dealline(self, file_list):
        '''
        Usage: 处理box中的数据
        '''
        # 清空现有的 Treeview 数据
        x = self.box.get_children()
        for item in x:
            self.box.delete(item)
        # 插入新的文件名到 Treeview
        for file_name in file_list:
            self.box.insert('', 'end', values=[file_name])
        # while 1:
        #     try:
        #         line = next(op)
        #     except StopIteration as e:
        #         break
        #     else:
        #         result = patch.match(line)
        #         self.box.insert('', 'end', values=[result.group(i) for i in range(1, 5)])

    def isquit(self):
        '''
        Usage: 询问是否退出窗口
        '''
        is_quit = askyesno('警告', '你是否确定退出，这将会关闭窗口')
        if is_quit:
            self.quit()

    def download(self):
        '''
        Usage: 调用Client类的download_file函数进行下载
        '''
        curItem = self.box.focus()
        print(self.box.item(curItem))
        filename = self.box.item(curItem)['values'][0]

        showinfo('提示！', message='点击确认文件将开始后台下载')
        thread = threading.Thread(target=self.client.download_file, args=(filename,))
        thread.start()


class UploadFrame(Frame):  
    '''
    Description: 上传文件页面
    '''
    def __init__(self, master = None, client = None):
        Frame.__init__(self, master)
        self.root = master  # 定义内部变量root
        self.filePath = StringVar()
        self.client = client
        self.createPage()

    def createPage(self):
        '''
        Usage: 创建页面
        '''

        Label(self).grid(row=0, stick=W, pady=10)
        Label(self, text='请选择要上传的文件: ', font=('宋体', 12)).grid(row=1, stick=W, pady=10)
        Entry(self, textvariable=self.filePath, width=50, font=('宋体', 12)).grid(row=1, column=1, stick=E)
        Button(self, text=' 选择文件 ', command=self.select_file, font=('宋体', 10), bg='#D0D3D4').grid(row=1, column=2, stick=E, padx=10)
        Button(self, text='上传', bg='#3498DB', command=self.upload, font=('宋体', 12)).grid(row=2, column=1, stick=W, pady=10, ipadx=50)
        Button(self, text='重置', bg='#E74C3C',command=self.reset, font=('宋体', 12)).grid(row=2, column=1, stick=E, pady=10, ipadx=50)


    def select_file(self):
        '''
        Usage: 选择上传文件
        '''
        path = filedialog.askopenfilename()  # 获得选择好的文件
        self.filePath.set(path)

    def upload(self):
        '''
        Usage: 调用Client类的upload_file函数进行文件上传
        '''
        path = self.filePath.get()
        showinfo('提示！', message='点击确认文件将开始后台上传')
        # 开启线程上传
        thread = threading.Thread(target=self.client.upload_file, args=(path,))
        thread.start()
        self.filePath.set("")

    def reset(self):
        '''
        重置输入框
        '''
        self.filePath.set("")


class AboutFrame(Frame):  
    '''
    Description: 关于信息
    '''
    def __init__(self, master = None, client = None):
        Frame.__init__(self, master)
        self.root = master  # 定义内部变量root
        self.createPage()
        self.client = client

    def createPage(self):
        '''
        Usage: 创建页面
        '''
        Label(self, text='关于', font=('黑体', 14)).pack(pady=10)
        about_text = "安全文件传输客户端 v1.0\n开发者: YoelMiko\n联系方式: yoelmiko888@gmail.com"
        Label(self, text=about_text, font=('黑体', 12)).pack(pady=10)
