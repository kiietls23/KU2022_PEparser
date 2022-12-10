import pefile
import sys
from PyQt5.QtWidgets import *
from PyQt5 import uic   # ui 파일을 사용하기 위한 모듈 import
from PyQt5.QtGui import *#Qfont사용하기위해import


#UI파일 연결 코드
UI_class = uic.loadUiType("just_temp.ui")[0]


class MyWindow(QDialog, UI_class):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        
        self.inputb.clicked.connect(self.inputf)
        self.sectionButton.clicked.connect(self.butfunc)
        self.headerButton.clicked.connect(self.butfunc2)
        self.tree.itemClicked.connect(self.clicktree)

    def clicktree(self, it, col):
        #print(it.text(0))
        select = it.text(0)
        flag = True
        if select == "DOS HEADER":
            h = pe.DOS_HEADER.dump_dict()
        elif select == "FILE HEADER":
            h = pe.FILE_HEADER.dump_dict()
        elif select == "OPTIONAL HEADER":
            h = pe.OPTIONAL_HEADER.dump_dict()
        else:
            for s in pe.sections:
                if select==s.Name.decode():
                    h = s.dump_dict()
                    flag = True
                    break
                else:
                    flag = False
        if flag:
            self.textBrowser.clear()
            self.print_info(h)
            
            
    def inputf(self):
        self.setfont()#폰트설정
        path = self.lineEdit.text()
        global pe
        global packed
        packed = 0
        pe = pefile.PE(path)
        print(path)
        self.textBrowser.setPlainText(path)
        for s in pe.sections:
            if "UPX" in s.Name.decode():
                packed = 1
                print("UPX Packed")
                self.textBrowser.append("UPX Packed")
                break
        if packed != 1:
            self.summary.clear()
            self.summ()
            self.tree.header().setVisible(False)
            dosHeader = QTreeWidgetItem(self.tree)
            dosHeader.setText(0,"DOS HEADER")
            ntHeader = QTreeWidgetItem(self.tree)
            ntHeader.setText(0, "NT HEADER")
            fileH = QTreeWidgetItem(ntHeader)
            fileH.setText(0, "FILE HEADER")
            optionH = QTreeWidgetItem(ntHeader)
            optionH.setText(0, "OPTIONAL HEADER")
            Sections = QTreeWidgetItem(self.tree)
            Sections.setText(0, "Sections")
            sss = []
            for s in pe.sections:
                news = QTreeWidgetItem(Sections)
                news.setText(0, s.Name.decode())
                sss.append(news)

    def butfunc(self):
        self.textBrowser.clear()
        for s in pe.sections: # section 정보 가져오기
            #print(s.Name.decode())
            self.textBrowser.append(s.Name.decode())
            sd = s.dump_dict() # dictionary 형태로 가져와서 print_info호출
            self.print_info(sd)
    
    def butfunc2(self):
        self.textBrowser.clear()
        hinfo=[pe.DOS_HEADER.dump_dict(), pe.NT_HEADERS.dump_dict(), pe.FILE_HEADER.dump_dict(), pe.OPTIONAL_HEADER.dump_dict()]
        for h in hinfo:
            #print("[", h['Structure'], "]")
            self.textBrowser.append("["+h['Structure']+"]")
            self.print_info(h)
    def printdos(self, h):
        self.textBrowser.clear()
        h = pe.DOS_HEADER.dump_dict()
        self.textBrowser.append("["+h['Structure']+"]")
        self.print_info(h)
    
    def setfont(self):
        fontvar = QFont("Consolas",10)
        self.textBrowser.setCurrentFont(fontvar)
        self.summary.setCurrentFont(fontvar)
        
    def print_info(self,d):
        del d['Structure'] # 필요없는 정보 삭제
        tlist=[['Name','Offset','RAW','Value'],['-'*30,'-'*10,'-'*10,'-'*10]]
        for k in d.keys(): # 딕셔너리의 모든 key에 대해 반복 (key=구조체 멤버변수이름에 해당/ value=딕셔너리형태의 멤버변수정보)
            tp = d[k]
            # 멤버변수이름, 오프셋, fileoffset(RAW), 값을 요소로 하는 리스트를 tlist에 append
            tlist.append([k, hex(tp['Offset']), hex(tp['FileOffset']), hex(tp['Value']) if type(tp['Value'])==int else tp['Value']])
        # 모든 key에 대한 정보를 tlist에 추가한 후
        # 형태 맞춰서 tlist를 출력
        #self.setfont()#폰트설정
        for item in tlist:
            #print(f'{item[0]:30s}| {item[1]:10}| {item[2]:10}| {item[3]:10}')
            self.textBrowser.append(f'{item[0]:30s}| {item[1]:10}| {item[2]:10}| {item[3]:10}')
        self.textBrowser.append("")
    def summ(self):
        #섹션 이름, NumberOfSections, TimeDateStamp, BaseOfCode, ImageBase
        row = 0
        col = 1
        self.sumtable.setColumnCount(col)
        self.sumtable.setRowCount(pe.FILE_HEADER.NumberOfSections)
        self.sumtable.setHorizontalHeaderItem(0, QTableWidgetItem("section name"))
        self.summary.append("NumberOfSections :"+str(pe.FILE_HEADER.NumberOfSections))
        for s in pe.sections:
            self.sumtable.setItem(row,0,QTableWidgetItem(s.Name.decode()))
            row=row+1
        self.summary.append("TimeDateStamp : "+pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'])
        self.summary.append("ImageBase : "+str(hex(pe.OPTIONAL_HEADER.ImageBase)))
        self.summary.append("BaseOfCode : "+str(hex(pe.OPTIONAL_HEADER.BaseOfCode)))
        
    def sumt(self):
        row = 0
        col = 1
        self.sumtable.setColumnCount(col)
        self.sumtable.setRowCount(pe.FILE_HEADER.NumberOfSections)
        self.sumtable.setHorizontalHeaderItem(0, QTableWidgetItem("section name"))
        for s in pe.sections:
            self.sumtable.setItem(row,0,QTableWidgetItem(s.Name.decode()))
            row=row+1

app = QApplication(sys.argv)
Window = MyWindow() 
Window.show()
app.exec_()
