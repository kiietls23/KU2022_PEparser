import pefile

def print_info(d):
    del d['Structure']
    tlist=[['Name','Offset','RAW','Value'],['-'*30,'-'*10,'-'*10,'-'*10]]
    for k in d.keys():
        tp = d[k]
        tlist.append([k, hex(tp['Offset']), hex(tp['FileOffset']), hex(tp['Value']) if type(tp['Value'])==int else tp['Value']])
    for item in tlist:
        print(f'{item[0]:30s}| {item[1]:10}| {item[2]:10}| {item[3]:10}')
    print()

path = input("분석할 파일 경로를 입력해주세요 >> ")
print()
pe = pefile.PE(path)

hinfo=[pe.DOS_HEADER.dump_dict(), pe.NT_HEADERS.dump_dict(), pe.FILE_HEADER.dump_dict(), pe.OPTIONAL_HEADER.dump_dict()]

for h in hinfo:
    print("[", h['Structure'], "]")
    print_info(h)
for s in pe.sections:
    print(s.Name.decode())
    sd = s.dump_dict()
    print_info(sd)
