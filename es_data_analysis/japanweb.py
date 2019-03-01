import os
from es_data_analysis.constants import generate_file_name, IPS_FILE_NAME_PREFIX
from es_data_analysis.database_op import connect_db, insert_db

conn = connect_db()


PURE_IPS_FILE_NAME_PREFIX = 'pure_ips_'
INNER_IPS_FILE_NAME_PREFIX = 'inner_ips_'
OUTER_IPS_FILE_NAME_PREFIX = 'outer_ips_'
COMMUNICATION_FILE_PREFIX = 'communication_'


def extract_ips_from_single_file(file_name_list):
    """
    统计所有外部ip是202.106.0.20的所有连接，统计其中的连接情况：内部主机，时间，
    """
    ips_file, commication_file = [file_name for file_name in file_name_list]
    f = open(ips_file, 'r')
    commication = set()
    for line in f.readlines():
        info = line.split(',')
        external_ip = info[1]
        if external_ip != "202.106.0.20":
            continue
        inner_ip = info[2]
        outer_ip = info[3]
        start_time = info[4]
        end_time = info[5]
        commication.add((external_ip, inner_ip, outer_ip, start_time, end_time))
    f.close()
    # write_ips_to_file(commication_file, commication)
    insert_into_database(commication)


def write_ips_to_file(file_name, data):
    if os.path.exists(file_name):
        os.remove(file_name)
    desc = 'len of data: {0}'.format(len(data))
    f = open(file_name, 'a+')
    f.write(desc + '\n')
    for item in data:
        line_desc = '{0}'.format(item) + '\n'
        f.write(line_desc)


def get_desc(file_name, item, value):
    desc = None
    if 'in2ex_counter_' in file_name:
        strange_ip = item
        count = value[0]
        timestamp = value[1]
        # print('strange_ip: {0}, count: {1}, timestamp: {2}'.format(strange_ip, count, timestamp))
        desc = '{0},{1},{2}\n'.format(strange_ip, count, timestamp)
    elif 'connection_' in file_name:
        ex_ip = item[0]
        inner_ip = item[1]
        start_time = value[0]
        end_time = value[1]
        count = value[2]
        desc = '{0},{1},{2},{3},{4}'.format(ex_ip, inner_ip, count, start_time, end_time)
    return desc


def write_dict_to_file(file_name, data):
    if os.path.exists(file_name):
        os.remove(file_name)
    f = open(file_name, 'a+')
    desc = 'len of data: {0}'.format(len(data))
    f.write(desc + '\n')
    for item in data:
        value = data[item]
        desc = get_desc(file_name, item, value)
        if desc:
            f.write(desc)


def extract_ips_from_file_list(shift):
    # print('shift= {0}'.format(shift))
    ips_file_list = generate_file_name(IPS_FILE_NAME_PREFIX, shift)
    communication_file_list = generate_file_name(COMMUNICATION_FILE_PREFIX, shift)

    # 从ip_*文件中读取出原始数据，将与202.106.0.20通信的信息插入communication_*文件中
    for i in range(shift):
        ips_file = ips_file_list[i]
        if os.path.exists(ips_file):
            print('file_name: {0}'.format(ips_file))
            communication_file = communication_file_list[i]
            file_name_list = [ips_file, communication_file]
            extract_ips_from_single_file(file_name_list)
            print('finish one file!')


def insert_into_database(communications):
    table_name = 'ka_counter'
    if not communications:
        return

    sql = "insert into {0} (external_ip, inner_ip, start_time, end_time) VALUES".format(table_name)
    for index, item in enumerate(communications):
        external_ip = item[0]
        inner_ip = item[1]
        start_time = item[3]
        end_time = item[4]
        # print('enum  {0}, {1}, {2}, {3}'.format(external_ip, inner_ip, start_time, end_time))
        if index == 0:
            sql += "('{0}', '{1}', '{2}', '{3}')".format(external_ip, inner_ip, start_time, end_time)
        else:
            sql += ", ('{0}', '{1}', '{2}', '{3}')".format(external_ip, inner_ip, start_time, end_time)
    insert_db(conn, sql)


if __name__ == '__main__':
    # extract_ips_from_file()
    shift = 30
    extract_ips_from_file_list(shift)
