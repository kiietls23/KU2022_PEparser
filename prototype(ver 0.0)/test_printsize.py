# 사이즈 출력 구현하려고 시도 중
# Portable Executable reader module import
import pefile

# 헤더정보를 출력하는 함수
# PE구조정보를 dictionary 타입의 인수로 받아서 출력
def print_info(d):
    del d['Structure'] # 필요없는 정보 삭제
    tlist=[['Name','Offset','Size','RAW','Value'],['-'*30,'-'*10,'-'*10,'-'*10,'-'*10]]
    temp = 0
    for k in d.keys(): # 딕셔너리의 모든 key에 대해 반복 (key=구조체 멤버변수이름에 해당/ value=딕셔너리형태의 멤버변수정보)
        tp = d[k]
        if temp != 0:
            size = tp['Offset']- temp
        else:
            size = tp['Offset']
        # 멤버변수이름, 오프셋, 크기, fileoffset(RAW), 값을 요소로 하는 리스트를 tlist에 append
        tlist.append([k, hex(tp['Offset']), hex(size), hex(tp['FileOffset']), hex(tp['Value']) if type(tp['Value'])==int else tp['Value']])
        temp = tp['Offset']
    # 모든 key에 대한 정보를 tlist에 추가한 후
    # 형태 맞춰서 tlist를 출력
    for item in tlist:
        print(f'{item[0]:30s}| {item[1]:10}| {item[2]:10}| {item[3]:10}| {item[4]:10}')
    print()

# 프로그램 시작
# 파일 경로를 입력받음
path = input("분석할 파일 경로를 입력해주세요 >> ")
print()
pe = pefile.PE(path) # PE구조정보불러옴

# 각 header 정보를 dictionary type으로 가져옴
hinfo=[pe.DOS_HEADER.dump_dict(), pe.NT_HEADERS.dump_dict(), pe.FILE_HEADER.dump_dict(), pe.OPTIONAL_HEADER.dump_dict()]

for h in hinfo:
    print("[", h['Structure'], "]")
    print_info(h)
for s in pe.sections: # section 정보 가져오기
    print(s.Name.decode())
    sd = s.dump_dict() # dictionary 형태로 가져와서 print_info호출
    print_info(sd)
