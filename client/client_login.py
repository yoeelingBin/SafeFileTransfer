from tkinter import *
from tkinter.messagebox import *
from client_main import MainPage
from client import Client

class LoginPage(object):
    '''
    Description: 客户端登录页面
    '''
    def __init__(self, master=None):
        self.root = master  # 定义内部变量root
        self.root.geometry('450x300')  # 设置窗口大小
        self.root.title('安全文件传输系统')
        self.username = StringVar()
        self.password = StringVar()
        self.createPage()

    def createPage(self):
        '''
        Usage: 创建页面
        '''
        self.page = Frame(self.root)  # 创建Frame
        self.page.pack()
        canvas = Canvas(self.page, height=300, width=500)
        canvas.pack(side='top')


        Label(self.page, text='用户名:').place(x=120, y=100)
        Entry(self.page, textvariable=self.username).place(x=200, y=100)
        Label(self.page, text='密  码:').place(x=120, y=140)
        Entry(self.page, textvariable=self.password, show='*').place(x=200, y=140)
        Button(self.page, text='登录', command=self.login).place(x=140, y=180)
        Button(self.page, text='注册', command=self.register).place(x=210, y=180)
        #Button(self.page, text='退出', command=self.page.quit).place(x=280, y=180)
        self.username.set('testuser')
        self.password.set('testpasswd')

    def login(self):
        '''
        Usage: 登录
        '''
        name = self.username.get()
        password = self.password.get()
        client = Client()
        client.connect()

        loginStatus = client.login(name, password)

        # 用户名密码不能为空
        if name == '' or password == '':
            showerror(message='用户名或密码为空')
        else:
            # 判断用户名和密码是否匹配
            if loginStatus:
                showinfo(title='welcome',message='欢迎您：' + name)
                #记录用户名和密码
                client.username = name
                client.password = password
                self.page.destroy()
                MainPage(self.root,client)
            else:
                showerror(message='用户名或密码错误')

    def register(self):
        '''
        Usage: 注册新用户
        '''
        # 确认注册时的相应函数
        def sign_up():
            # 获取输入框内的内容
            nn = new_name.get()
            np = new_pwd.get()
            npf = new_pwd_confirm.get()


            if np == '' or nn == '':
                showerror('错误', '用户名或密码为空')
            elif np != npf:
                showerror('错误', '密码前后不一致')
            else:
                client = Client()
                client.connect()
                stat = client.register(nn,np)
                if stat:
                    showinfo('欢迎', '注册成功')
                    # 注册成功关闭注册框
                    window_sign_up.destroy()
                else :
                    showerror('错误', '用户名已存在')

        # 新建注册界面
        window_sign_up = Toplevel(self.page)
        window_sign_up.geometry('350x200')
        window_sign_up.title('注册')
        # 用户名变量及标签、输入框
        new_name = StringVar()
        Label(window_sign_up, text='用户名：').place(x=10, y=10)
        Entry(window_sign_up, textvariable=new_name).place(x=150, y=10)
        # 密码变量及标签、输入框
        new_pwd = StringVar()
        Label(window_sign_up, text='请输入密码：').place(x=10, y=50)
        Entry(window_sign_up, textvariable=new_pwd, show='*').place(x=150, y=50)
        # 重复密码变量及标签、输入框
        new_pwd_confirm = StringVar()
        Label(window_sign_up, text='请再次输入密码：').place(x=10, y=90)
        Entry(window_sign_up, textvariable=new_pwd_confirm, show='*').place(x=150, y=90)
        # 确认注册按钮及位置
        bt_confirm_sign_up = Button(window_sign_up, text='确认注册', command=sign_up)
        bt_confirm_sign_up.place(x=150, y=130)

if __name__ == "__main__":
    root = Tk()
    app = LoginPage(root)
    root.mainloop()
