import os
from es_data_analysis.constants import generate_file_name, IPS_FILE_NAME_PREFIX, EXTERNAL_IPS_FILE_NAME_PREFIX, \
    CONNECTION_FILE_NAME_PREFIX, CONNECTION_COUNTER_FILE_NAME_PREFIX

PURE_IPS_FILE_NAME_PREFIX = 'pure_ips_'
INNER_IPS_FILE_NAME_PREFIX = 'inner_ips_'
OUTER_IPS_FILE_NAME_PREFIX = 'outer_ips_'


def extract_ips_from_single_file(file_name_list):
    """
    三元组(external_ip, inner_ip, outer_ip)的集
    所有外部IP地址的集合合
    所有内部专用IP地址的集合
    所有内部转换后的IP地址的集合
    connection_*文件内容：外部IP，内部专用IP(指示内部主机)，在一天内的总连接数，最早的连接时间，最晚结束时间
    in2ex_counter_*文件内容：外部IP，一天内和它相连的内部主机总数，最早连接的时间
    """
    ips_file, pure_ips_file, external_ips_file, inner_ips_file, outer_ips_file, \
    connection_file, connection_counter_file = [file_name for file_name in file_name_list]
    f = open(ips_file, 'r')
    pure_ips = set()
    external_ips = set()
    inner_ips = set()
    outer_ips = set()
    connection_ips = {}
    in2ex_per_day = {}
    for line in f.readlines():
        info = line.split(',')
        # print('info: {0}'.format(info))
        # print('len of info: {0}'.format(len(info)))
        # print('connection_counter_file: {0}'.format(connection_counter_file))
        external_ip = info[1]
        inner_ip = info[2]
        outer_ip = info[3]
        start_time = info[4]
        end_time = info[5]
        pure_ips.add((external_ip, inner_ip, outer_ip))
        external_ips.add(external_ip)
        inner_ips.add(inner_ip)
        outer_ips.add(outer_ip)

        # 记录每个外部IP地址与内部主机的连接次数
        if (external_ip, inner_ip) in connection_ips:
            connection_ips[(external_ip, inner_ip)][2] += 1
            if connection_ips[(external_ip, inner_ip)][0] > start_time:
                connection_ips[(external_ip, inner_ip)][0] = start_time
            if connection_ips[(external_ip, inner_ip)][1] < end_time:
                connection_ips[(external_ip, inner_ip)][1] = end_time
        else:
            connection_ips[(external_ip, inner_ip)] = [start_time, end_time, 1]

        # 记录每个外部IP每天与多少个内部主机相连（外部IP连接的内部主机个数）
        if external_ip in in2ex_per_day:
            in2ex_per_day[external_ip][0] += 1
            if in2ex_per_day[external_ip][1] > start_time:  # 选择最早的那个时间作为外部IP第一次出现的时间
                in2ex_per_day[external_ip][1] = start_time
        else:
            in2ex_per_day[external_ip] = [1, start_time]
    f.close()
    # write_ips_to_file(pure_ips_file, pure_ips)
    # write_ips_to_file(external_ips_file, external_ips)
    write_ips_to_file(inner_ips_file, inner_ips)
    # write_ips_to_file(outer_ips_file, outer_ips)
    # write_dict_to_file(connection_file, connection_ips)
    # write_dict_to_file(connection_counter_file, in2ex_per_day)


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


def compare_outer_ips_per_day(outer_ips_file_list):
    all_outer_ips = set({})
    diff_outer_ips = set({})
    for file_name in outer_ips_file_list:
        if not os.path.exists(file_name):
            continue
        with open(file_name, 'r') as f:
            for item in f.readlines():
                if item.find('len') != -1:  # 如果是第一行
                    continue
                if item not in all_outer_ips:
                    all_outer_ips.add(item)
                # 等价写法
                # all_outer_ips = all_outer_ips.union({item})
        if not diff_outer_ips:
            diff_outer_ips = all_outer_ips
        else:
            diff_outer_ips = diff_outer_ips & all_outer_ips

    print('len of all_outer_ips: {0}'.format(len(all_outer_ips)))
    print('len of diff_outer_ips: {0}'.format(len(diff_outer_ips)))
    for item in all_outer_ips:
        print('item: {0}'.format(item))


def extract_ips_from_file_list(shift):
    print('shift= {0}'.format(shift))
    ips_file_list = generate_file_name(IPS_FILE_NAME_PREFIX, shift)
    pure_ips_file_list = generate_file_name(PURE_IPS_FILE_NAME_PREFIX, shift)
    external_ips_file_list = generate_file_name(EXTERNAL_IPS_FILE_NAME_PREFIX, shift)
    inner_ips_file_list = generate_file_name(INNER_IPS_FILE_NAME_PREFIX, shift)
    outer_ips_file_list = generate_file_name(OUTER_IPS_FILE_NAME_PREFIX, shift)
    connection_file_list = generate_file_name(CONNECTION_FILE_NAME_PREFIX, shift)
    connection_counter_file_list = generate_file_name(CONNECTION_COUNTER_FILE_NAME_PREFIX, shift)

    for i in range(shift):
        ips_file = ips_file_list[i]
        print('file_name: {0}'.format(ips_file))
        if os.path.exists(ips_file):
            print('file_name: {0}'.format(ips_file))
            pure_ips_file = pure_ips_file_list[i]
            external_ips_file = external_ips_file_list[i]
            inner_ips_file = inner_ips_file_list[i]
            outer_ips_file = outer_ips_file_list[i]
            connection_file = connection_file_list[i]
            connection_counter_file = connection_counter_file_list[i]
            file_name_list = [ips_file, pure_ips_file, external_ips_file, inner_ips_file, outer_ips_file,
                              connection_file, connection_counter_file]
            extract_ips_from_single_file(file_name_list)
            print('finish one file!')

    compare_outer_ips_per_day(outer_ips_file_list)


if __name__ == '__main__':
    # extract_ips_from_file()
    shift = 30
    extract_ips_from_file_list(shift)
