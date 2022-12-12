import pefile
import sys
import os
import os.path
from PyQt5.QtWidgets import *
from PyQt5 import uic   # ui 파일을 사용하기 위한 모듈 import
from PyQt5.QtGui import *#Qfont사용하기위해import

#UI파일 연결 코드
def resource_path(relative_path):
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

form = resource_path("just_temp.ui")
UI_class = uic.loadUiType(form)[0]

class MyWindow(QDialog, UI_class):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        
        self.inputb.clicked.connect(self.inputf)
        self.tree.itemClicked.connect(self.clicktree)
        self.showAll.clicked.connect(self.showall)

    def inputf(self):
        self.setfont()#폰트설정
        self.summary.clear()#요약창비우기
        self.tree.clear()#트리비우기
        self.baseofc.clear()
        self.imageb.clear()
        self.analy.clear()
        self.sumtable.clear()
        path = self.lineEdit.text()
        global pe
        global packed
        global error
        packed = 0
        error = 0
        self.textBrowser.setPlainText(path)
        if os.path.isfile(path)==False:
            self.textBrowser.append("파일이 존재하지 않습니다.")
            self.summary.append("파일이 존재하지 않습니다.")
            error = 1
            return
        pe = pefile.PE(path)
        for s in pe.sections:
            if "UPX" in s.Name.decode():
                self.highlight()#강조
                packed = 1
                self.textBrowser.append("UPX Packed")
                self.summary.setPlainText("UPX Packed")
                break
        self.setfont()#강조해제
        self.summ()
        self.setTree()

    def setTree(self):
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
        
    def clicktree(self, it, col):
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
    
    def showall(self):
        if error:
            return
        self.textBrowser.clear()
        hinfo=[pe.DOS_HEADER.dump_dict(), pe.NT_HEADERS.dump_dict(), pe.FILE_HEADER.dump_dict(), pe.OPTIONAL_HEADER.dump_dict()]
        for h in hinfo:
            self.textBrowser.append("["+h['Structure']+"]")
            self.print_info(h)
        for s in pe.sections: # section
            self.textBrowser.append(s.Name.decode())
            sd = s.dump_dict()
            self.print_info(sd)
    
    def summ(self):
        #섹션 이름, NumberOfSections, TimeDateStamp, BaseOfCode, ImageBase
        row = 0
        col = 1
        self.sumtable.setColumnCount(col)
        self.sumtable.setRowCount(pe.FILE_HEADER.NumberOfSections)
        self.sumtable.setHorizontalHeaderItem(0, QTableWidgetItem("section info"))
        self.summary.append("NumberOfSections :"+str(pe.FILE_HEADER.NumberOfSections))
        for s in pe.sections:
            self.sumtable.setItem(row,0,QTableWidgetItem(s.Name.decode()))
            row=row+1
        self.summary.append("TimeDateStamp : "+pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'])
        self.summary.append("ImageBase : "+str(hex(pe.OPTIONAL_HEADER.ImageBase)))
        self.summary.append("BaseOfCode : "+str(hex(pe.OPTIONAL_HEADER.BaseOfCode)))
        ib = pe.OPTIONAL_HEADER.ImageBase
        bc = pe.OPTIONAL_HEADER.BaseOfCode
        self.imageb.setPlainText(str(hex(ib)))
        self.baseofc.setPlainText(str(hex(bc)))
        self.analy.setPlainText(str(hex(ib+bc)))
    
    def setfont(self):
        fontvar = QFont("Consolas",10)
        color = QColor(0,0,0)
        self.textBrowser.setCurrentFont(fontvar)
        self.summary.setCurrentFont(fontvar)
        self.summary.setTextColor(color)
        
    def highlight(self):
        fontvar = QFont("Consolas", 12, QFont.Bold)
        color = QColor(255,0,0)
        self.summary.setCurrentFont(fontvar)
        self.summary.setTextColor(color)
        
    def print_info(self,d):
        del d['Structure'] # 필요없는 정보 삭제
        tlist=[['Name','Offset','RAW','Value'],['-'*30,'-'*10,'-'*10,'-'*10]]
        for k in d.keys(): # 딕셔너리의 모든 key에 대해 반복 (key=구조체 멤버변수이름에 해당/ value=딕셔너리형태의 멤버변수정보)
            tp = d[k]
            # 멤버변수이름, 오프셋, fileoffset(RAW), 값을 요소로 하는 리스트를 tlist에 append
            tlist.append([k, hex(tp['Offset']), hex(tp['FileOffset']), hex(tp['Value']) if type(tp['Value'])==int else tp['Value']])
        for item in tlist:
            self.textBrowser.append(f'{item[0]:30s}| {item[1]:10}| {item[2]:10}| {item[3]:10}')
        self.textBrowser.append("")

app = QApplication(sys.argv)
Window = MyWindow() 
Window.show()
app.exec_()
