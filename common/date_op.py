from datetime import datetime, timedelta


def generate_day_seq(start_day, day_range=1, date_format="%Y.%m.%d", forward=1):
    """
    获取100个如2018.10.01的日期字符串组成的列表
    :param date_format:
    :return:
    """
    dt_str_seq = []
    dt = datetime.strptime(start_day, date_format)
    for i in range(day_range):
        # print(dt.strftime(date_format))
        dt_str = dt.strftime(date_format)
        dt_str_seq.append(dt_str)
        dt = dt + timedelta(days=forward)
    return dt_str_seq


def str2date(date_str):
    """
    解析日期字符串为日期对象
    :param date_str: 如1995-05-03T210000-0700
    :return:
    """
    pass

