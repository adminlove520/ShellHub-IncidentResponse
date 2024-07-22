import re


# @author anonymous 
# @Date: 2024-7-22 
# 使用前请定义'dbname'、'*.sql'
dbname = ''

with open('*.sql', 'r', encoding='utf-8') as f:
    for i,db in enumerate(f):
        dbnamea = re.findall('Table structure for (.*)', db)
        if dbnamea:
            dbname = dbnamea[0]
            print('正在写入%s' % dbname)
        if dbname != '':
            with open('sqls_datas/{}.sql'.format(dbname), 'a+', encoding='utf-8') as fw:
                fw.write(db)
print('split sql file done!')
