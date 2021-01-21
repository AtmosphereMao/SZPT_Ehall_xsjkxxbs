from SZPT_Ehall import *
import datetime
import schedule

def main():
    print("Now Time: %s" % (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    flag = True
    while flag:
        if login():
            if send_info():
                print("提交成功")
                flag = False
            else:
                print("提交失败")
        else:
            print("登录失败")
    print("-- Today End %s -------------------------------" % (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

def work_queue():
    schedule.every().day.at("08:00").do(main)
    while True:
        schedule.run_pending()



if __name__ == '__main__':
    work_queue()
