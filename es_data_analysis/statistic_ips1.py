import os
import re

from elasticsearch import Elasticsearch
from elasticsearch import helpers
from es_data_analysis.constants import generate_file_name, generate_index_name_list, IPS_FILE_NAME_PREFIX

HOST = '192.168.105.132:9200'
DOC_TYPE = 'logs'
es = Elasticsearch(hosts=HOST)


def normalize_message(raw_message):
    """
    :param raw_message:
        输入的需要切分的原始消息，如tcp;52.114.88.28;443;192.168.3.153;2607--->219.224.171.10;13424;[2018/11/11 07:45:32-2018/11/11 07:46:36]
        需要切成：tcp 52.114.88.28;443 192.168.3.153 219.224.171.10 2018/11/11 07:45:32 2018/11/11 07:46:36
    :return: 返回一个规范化后的消息，若输入的消息无法规范化，则返回None
    """
    exp = '\d+\.\d+\.\d+\.\d+'
    if re.search(exp, raw_message) is None:
        return None

    # 获取协议
    pos0 = raw_message.find(';')
    protocol = raw_message[:pos0]

    # 获取外部IP
    pos1 = raw_message.find(';')
    end1 = raw_message.find(';', pos1 + 1)
    external_ip = raw_message[pos1 + 1: end1]

    # 获取转换前的内部IP
    pos2 = raw_message.find(';', end1 + 1)
    end2 = raw_message.find(';', pos2 + 1)
    inner_ip = raw_message[pos2 + 1: end2]

    # 获取转换后的IP
    pos3 = raw_message.find('--->')
    end3 = raw_message.find(';', pos3)
    outer_ip = raw_message[pos3 + len('--->'):end3]

    # 连接开始时间
    pos1 = raw_message.find('[', end3) + 1
    end1 = raw_message.find('-', pos1)
    start_time = raw_message[pos1: end1]

    # 连接结束时间
    end2 = raw_message.find(']', end1)
    end_time = raw_message[end1 + 1: end2]
    message = '{0},{1},{2},{3},{4},{5}'.format(protocol, external_ip, inner_ip, outer_ip, start_time, end_time)
    # print('===============================================')
    # print('raw_message: {0}'.format(raw_message))
    # print('protocol: {0}'.format(protocol))
    # print('message: {0}'.format(message))
    # print('external_ip: {0}'.format(external_ip))
    # print('inner_ip: {0}'.format(inner_ip))
    # print('outer_ip: {0}'.format(outer_ip))
    # print('start_time: {0}'.format(start_time))
    # print('end_time: {0}'.format(end_time))
    # print('*********************************************')
    return message


def get_message(raw_message):
    """
    提取原始消息中需要的部分，进行规范化，然后返回
    :param raw_message:
    :return:
    """
    pos = raw_message.find('DEV_TYPE')
    start = raw_message.find(' ', pos) + 1
    message = raw_message[start:]
    message = normalize_message(message)
    return message


def write_messages_into_file(ips_file_name, genator):
    """
    从生成器中读取从一个索引中读出的NAT日志内容，写入文件中
    :param ips_file_name:
    :param genator:
    :return:
    """
    if os.path.exists(ips_file_name):
        os.remove(ips_file_name)
    f = open(ips_file_name, 'a+')

    # 无用代码，只用于调试
    num = 0
    failed = 0

    for item in genator:
        raw_message = item['_source']['message']
        message = get_message(raw_message)
        if message:
            f.write(message + '\n')

        # 无用，只用于调试
        # print('message: {0}'.format(message))
        # print('raw_message: {0}'.format(raw_message))
        # num += 1
        # if num % 5000 == 0:
        #     print('num: {0}'.format(num))

    f.close()

    # 无用代码，只用于调试
    # print('num: {0}, failed: {1}\\n'.format(num, failed))


def statistic_ips_in_one_day(index_name, ips_file_name):
    """
    从ES中查询指令索引中的数据，并写入文件中
    :param index_name: 读的索引名称
    :param ips_file_name: 写入的文件名称
    :return:
    """
    query_body = {
        "query": {
            "match_all": {}
        }
    }
    if es.indices.exists(index_name):
        result = es.search(index_name, DOC_TYPE, query_body)
        total = result['hits']['total']
        result = helpers.scan(es, index=index_name, doc_type=DOC_TYPE, query=query_body)
        genator = (con for con in result)
        write_messages_into_file(ips_file_name, genator)
        print('total: {0}\\n'.format(total))
        return total


def statistic_ips_in_nat(shift=5):
    """
    从一组索引中读取日志内容，并逐一写入文件中
    :param shift:
    :return:
    """
    ips_file_name_list = generate_file_name(IPS_FILE_NAME_PREFIX, shift)
    index_name_list = generate_index_name_list(shift)
    total_num = []
    for i in range(shift):
        index_name = index_name_list[i]
        ips_file_name = ips_file_name_list[i]
        total = statistic_ips_in_one_day(index_name, ips_file_name)
        total_num.append(total)
        print('index_name: {0}'.format(index_name))
        print('ips_file_name: {0}'.format(ips_file_name))
        print('finish file_name: {0}'.format(ips_file_name))


if __name__ == '__main__':
    shift = 30
    statistic_ips_in_nat(shift)
