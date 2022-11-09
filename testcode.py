import pefile
import struct
import datetime

path = ''#분석할 파일 경로 입력
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
