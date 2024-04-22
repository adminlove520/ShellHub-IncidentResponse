
#!/bin/bash  

# 定义日志文件路径，使用`date`命令获取当前的小时和日期，并以此命名日志文件  
logfile=/tmp/`date +%H-%F`.log  
#logfile=/var/`date +%H-%F`.log  
  
# 获取当前的小时数  
n=`date +%H`  
  
# 判断当前小时是否为0点或12点  
if [ $n -eq 00 ] || [ $n -eq 12 ]  
then  
    # 如果是0点或12点，则遍历目标目录下的所有文件，并清空其内容  
    # 使用`find`命令查找/data/log/目录下的所有文件（不包括目录），并使用`true > $i`命令清空文件内容  
    for i in `find /data/log/ -type f`  
    do  
        true > $i  
    done  
else  
    # 如果不是0点或12点，则遍历目标目录下的所有文件，并记录其大小  
    # 使用`find`命令查找/data/log/目录下的所有文件，并使用`du -sh $i`命令获取文件大小，然后追加到日志文件中  
    for i in `find /data/log/ -type f`  
    do  
        du -sh $i >> $logfile  
    done  
fi