import pefile

def print_header(d):
    print("[", d['Structure'], "]")
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

dosh=pe.DOS_HEADER.dump_dict()
nth=pe.NT_HEADERS.dump_dict()
fileh=pe.FILE_HEADER.dump_dict()
oph=pe.OPTIONAL_HEADER.dump_dict()
print_header(dosh)
print_header(nth)
print_header(fileh)
print_header(oph)
