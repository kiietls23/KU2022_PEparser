import pefile
import struct
import datetime

path = 'C:\\Users\\USER\\OneDrive - 고려대학교\\study\\2022-1\\역공학\\CRACKME1\\CRACKME1.EXE'
pe = pefile.PE(path)
print("파싱 시작 ...")
# DOS HEADER
for dos in pe.DOS_HEADER.dump():
    print(dos)
# NT HEADER
for fi in pe.FILE_HEADER.dump():
    print(fi)
for o in pe.OPTIONAL_HEADER.dump():
    print(o)
