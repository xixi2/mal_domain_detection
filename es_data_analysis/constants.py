from datetime import datetime, timedelta
import os

FILE_PATH_7 = 'ips_statistic_7'
FILE_PATH_14 = 'ips_statistic_14'
FILE_PATH_15 = 'ips_statistic_15'
FILE_PATH_30 = 'ips_statistic_30'
IPS_FILE_NAME_PREFIX = 'ips_'
INDEX_NAME_PREFIX = 'act-nat-'
EXTERNAL_IPS_FILE_NAME_PREFIX = 'external_ips_'
CONNECTION_FILE_NAME_PREFIX = 'connection_'
CONNECTION_COUNTER_FILE_NAME_PREFIX = 'in2ex_counter_'

# mysql表名
CONNECTION_TABLE_NAME = 'connections_copy2'        # 记录外部IP域内部主机连接次数
EXTERNAL_IPS_TABLE_NAME = 'external_ips'    # 记录外部IP连接的内部主机个数


file_path_dict = {
    7: FILE_PATH_7,
    14: FILE_PATH_14,
    15: FILE_PATH_15,
    30: FILE_PATH_30
}


def generate_date_str(shift, date_format="%Y_%m_%d"):
    """
    :param shift: 偏移天数，如果要产生从今天到15天以前的日期字符串，则shift=15
    :param date_format: 日期格式
    :return:
        如果今天是2018/11/21，
            date_format="%Y_%m_%d"，而那么返回则是2018_11_21
            date_format="%Y.%m.%d"，那么返回则是2018.11.21
    """
    now = datetime.now()
    date_str_list = []
    for i in range(shift):
        date_str = now.strftime(date_format)
        date_str_list.append(date_str)
        now = now - timedelta(days=1)
    return date_str_list


def generate_file_path(file_name, shift):
    file_path = file_path_dict[shift]
    file_path = os.path.join(file_path, file_name)
    # print('file_path: {0}'.format(file_path))
    return file_path


def generate_index_name_list(shift=30):
    date_format = "%Y.%m.%d"
    date_str_list = generate_date_str(shift, date_format)
    index_name_list = []
    for date_str in date_str_list:
        index_name = INDEX_NAME_PREFIX + date_str
        index_name_list.append(index_name)
    return index_name_list


def generate_file_name(file_name_prefix, shift=30):
    date_str_list = generate_date_str(shift)
    file_name_list = []
    for date_str in date_str_list:
        file_name = file_name_prefix + date_str + '.txt'
        file_name = generate_file_path(file_name, shift)
        file_name_list.append(file_name)
    return file_name_list


def str2timestamp(date_str="1542764232", ret_date_format="%b %d %Y %H:%M:%S"):
    """
    :param date_str: date_str是一个时间戳字符串
    :return:
        返回一个时间，如：2018-11-21 09:37:12
    """
    dist = float(date_str)
    time_stamp = datetime.fromtimestamp(dist)  # 此时time_stamp是一个datetime对象
    # time_stamp = time_stamp.strftime(ret_date_format)# 将上面的datetime对象按照指定的格式展示，如：2018-11-21 09:37:12
    time_stamp = str(time_stamp)
    # print('time_stamp: {0}'.format(time_stamp))  # 直接将datetime对象变成字符串
    return time_stamp


if __name__ == "__main__":
    str2timestamp()
