#!/bin/bash
# 定义5分钟以前的时间，用于过滤5分钟以前的日志
start_time=$(LC_TIME=en_US.UTF-8 date -d "-5 minutes" "+%d/%b/%Y:%H:%M")
# 定义为当前时间
end_time=$(LC_TIME=en_US.UTF-8 date "+%d/%b/%Y:%H:%M")
# 需要过滤的nginx日志
log="/data/nginx/log/user_access.log"
#排除列表，如有多个可以这样写 '116\\.179\\.37|116\\.177\\.37'
exclude_nets='116\\.179\\.37'

block_ip() {
    # 截取5分钟以前至当前的日志
    awk -v start="$start_time" -v end="$end_time" -F '[][]' '$2 >= start && $2 <= end' "$log" >/data/nginx/log/tmp_last_minute.log

    # 将所有ip都过滤出来，存到临时文件
    awk '{print $1}' /data/nginx/log/tmp_last_minute.log >/data/nginx/log/tmp_last_minute_ip.log

    # 处理IP，只留前面三位，排除、排序、去重，获取多于1500次请求的ip段，这个数字可以根据实际情况来调整
    awk -F '.' '{print $1"."$2"."$3"."}' /data/nginx/log/tmp_last_minute_ip.log | awk -v nets="$exclude_nets" '!($0 ~ nets)' | sort | uniq -c | sort -n | awk '$1 > 1500 {print $2}' >/data/nginx/log/bad_ip_minute.list

    # 当ip数大于0时，才会将它写入到封禁IP文件中
    ip_n=$(wc -l /data/nginx/log/bad_ip_minute.list | awk '{print $1}')
    if [ ${ip_n} -ne 0 ]; then
        for ip in $(cat /data/nginx/log/bad_ip_minute.list); do
            # 封ip，不能直接封ip段
            for ip2 in $(grep "^$ip" /data/nginx/log/tmp_last_minute_ip.log | sort -n | uniq); do
                /usr/sbin/iptables -I INPUT -s $ip2 -j REJECT
            done
        done
        # 将这些被封的IP记录到日志里
        echo "" >>/data/nginx/log/block_ip2.log
        echo "$(date) 封掉的IP段有：" >>/data/nginx/log/block_ip2.log
        cat /data/nginx/log/bad_ip_minute.list >>/data/nginx/log/block_ip2.log
    fi
    # 这句根据需要配置，我这里是因为5分钟的访问量也太多了，导致日志文件体积太大，所以清空一下
    cat /dev/null >$log
}

unblock_ip() {
    # 先清空计数
    /usr/sbin/iptables -Z
    # 等待2分钟
    sleep 120
    # 检查包个数小于5的ip段并记录到一个临时文件里，把它们标记为白名单IP
    /usr/sbin/iptables -nvL INPUT | grep REJECT | awk '$1<5 {print $8}' >/data/nginx/log/good_ip2.list
    n=$(wc -l /data/nginx/log/good_ip2.list | awk '{print $1}')
    if [ $n -ne 0 ]; then
        for ip in $(cat /data/nginx/log/good_ip2.list); do
            /usr/sbin/iptables -D INPUT -s $ip -j REJECT
        done
        echo "" >>/data/nginx/log/unblock_ip2.log
        echo "$(date) 解封的IP有：" >>/data/nginx/log/unblock_ip2.log
        cat /data/nginx/log/good_ip2.list >>/data/nginx/log/unblock_ip2.log
    fi
    # 当解封完白名单IP后，将计数器清零，进入下一个计数周期
    /usr/sbin/iptables -Z
}

# 检查命令行参数
if [[ $# -ne 1 ]]; then
    echo "请输入参数，block 或者 unblock。"
    exit 1
fi

# 根据命令行参数调用相应的函数
if [[ $1 == "block" ]]; then
    block_ip
elif [[ $1 == "unblock" ]]; then
    unblock_ip
else
    echo "参数输入错误。"
    exit 1
fi
