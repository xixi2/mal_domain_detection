import os

from es_data_analysis.constants import CONNECTION_FILE_NAME_PREFIX, CONNECTION_COUNTER_FILE_NAME_PREFIX, \
CONNECTION_TABLE_NAME, EXTERNAL_IPS_TABLE_NAME
from es_data_analysis.constants import generate_file_name
from es_data_analysis.database_op import connect_db, query_db, insert_db, update_db

conn = connect_db()

def save_connection_into_database(line):
    """
    记录每天的一个外部IP与内部主机之间的通信
    这里的次数是指每个外部IP与每个与之连接的内部主机之间每天的通信次数。
    :return:
    """
    try:
        info = line.strip('\n').split(',')
        # print('info: {0}'.format(info))
        # print('len of info: {0}'.format(len(info)))
        ex_ip = info[0]
        inner_ip = info[1]
        count = info[2]
        start_time = info[3]
        end_time = info[4]
        sql = "insert into {5} (external_ip, inner_ip, start_time, end_time, counter) VALUES ('{0}', '{1}', '{2}','{3}','{4}')"\
            .format(ex_ip, inner_ip, start_time, end_time, count, CONNECTION_TABLE_NAME)
        # print("sql: {0}".format(sql))
        insert_db(conn, sql)
    except Exception as e:
        print('error: {0}'.format(e))


def save_strange_ip_into_database(line):
    """
    把IP存入到数据库中
        如果IP已经在数据库中，则增加统计次数(这里的次数是指在一段时间内，一个外部IP连接的内部主机的累积个数)，
        否则IP是第一次出现，记录IP第一次出现的时间
            比对恶意IP数据库中的IP是否和这个IP相同。
    :param ip:
    :return:
    """
    try:
        info = line.strip('\n').split(',')
        # print('info: {0}'.format(info))
        # print('len of info: {0}'.format(len(info)))
        ip = info[0].strip('\n')
        timestamp = info[2]
        # if not timestamp:
        #     date_format = "%Y-%m-%d"
        #     timestamp = datetime.now().strftime(date_format)

        sql = "select * from %s where ip = '%s'" % (EXTERNAL_IPS_TABLE_NAME, ip)
        # print("sql: {0}".format(sql))
        res = query_db(conn, sql)   # 返回的结果是一个元组

        if len(res) == 0:           # 如果查询结果为数据库中已经存在，则不是该IP不是第一次出现,从查询结果中获取上一次的count
            count = 1
            sql = "insert into {0} (ip, timestamp, count) VALUES ('{1}', '{2}', {3})".format(EXTERNAL_IPS_TABLE_NAME, ip, timestamp, count)
            # print("sql: {0}".format(sql))
            insert_db(conn, sql)
        else:  # 否则，count=1
            count = len(res) + 1
            sql = "update {0} set count = {1} where ip = '{2}'".format(EXTERNAL_IPS_TABLE_NAME, count, ip)
            # print("sql: {0}".format(sql))
            update_db(conn, sql)
    except Exception as e:
        print('error: {0}'.format(e))


def save_into_database(file_name):
    print('file_name: {0}'.format(file_name))
    if not os.path.exists(file_name):
        return
    f = open(file_name, 'r')
    i = 0  # 如何判断是文件的第一行，因此文件的第一行记录的不是IP
    for line in f.readlines():
        if i == 0:
            i = 1
            continue
        else:
            # if 'in2ex_counter_' in file_name:
                # save_strange_ip_into_database(line)
            if 'connection_' in file_name:
                save_connection_into_database(line)


def main_history_for_ips(shift=14):
    """
    从外部IP地址文件中逐行读取所有的外部IP，存入数据库中
    :param shift:
    :return:
    """
    connection_file_list = generate_file_name(CONNECTION_FILE_NAME_PREFIX, shift)
    connection_counter_file_list = generate_file_name(CONNECTION_COUNTER_FILE_NAME_PREFIX, shift)
    for file_name in connection_file_list:
        save_into_database(file_name)
    # for file_name in connection_counter_file_list:
    #     save_into_database(file_name)


if __name__ == "__main__":
    main_history_for_ips(15)
