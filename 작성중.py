import pefile
import sys
from PyQt5.QtWidgets import *
from PyQt5 import uic   # ui 파일을 사용하기 위한 모듈 import

def print_info(d):
    del d['Structure'] # 필요없는 정보 삭제
    tlist=[['Name','Offset','RAW','Value'],['-'*30,'-'*10,'-'*10,'-'*10]]
    for k in d.keys(): # 딕셔너리의 모든 key에 대해 반복 (key=구조체 멤버변수이름에 해당/ value=딕셔너리형태의 멤버변수정보)
        tp = d[k]
        # 멤버변수이름, 오프셋, fileoffset(RAW), 값을 요소로 하는 리스트를 tlist에 append
        tlist.append([k, hex(tp['Offset']), hex(tp['FileOffset']), hex(tp['Value']) if type(tp['Value'])==int else tp['Value']])
    # 모든 key에 대한 정보를 tlist에 추가한 후
    # 형태 맞춰서 tlist를 출력
    for item in tlist:
        print(f'{item[0]:30s}| {item[1]:10}| {item[2]:10}| {item[3]:10}')
    print()

#UI파일 연결 코드
UI_class = uic.loadUiType("just_temp.ui")[0]


class MyWindow(QDialog, UI_class):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        
        self.inputb.clicked.connect(self.inputf)
        self.pushButton.clicked.connect(self.butfunc)
        self.pushButton_2.clicked.connect(self.butfunc2)

    def inputf(self):
        path = self.lineEdit.text()
        global pe
        global packed
        packed = 0
        pe = pefile.PE(path)
        print(path)
        for s in pe.sections:
            if "UPX" in s.Name.decode():
                packed = 1
                print("UPX Packed")
                break

    def butfunc(self):
        for s in pe.sections: # section 정보 가져오기
            print(s.Name.decode())
            sd = s.dump_dict() # dictionary 형태로 가져와서 print_info호출
            print_info(sd)
    def butfunc2(self):
        hinfo=[pe.DOS_HEADER.dump_dict(), pe.NT_HEADERS.dump_dict(), pe.FILE_HEADER.dump_dict(), pe.OPTIONAL_HEADER.dump_dict()]
        for h in hinfo:
            print("[", h['Structure'], "]")
            print_info(h)
        
        
# 프로그램 시작
# 파일 경로를 입력받음
#path = input("분석할 파일 경로를 입력해주세요 >> ")
#print()
#pe = pefile.PE(path) # PE구조정보불러옴
# 각 header 정보를 dictionary type으로 가져옴


app = QApplication(sys.argv) 
Window = MyWindow() 
Window.show()
app.exec_()
