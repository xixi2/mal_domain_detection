from selenium import webdriver
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary
from bs4 import BeautifulSoup
import pandas as pd
import time
from es_data_analysis.database_op import connect_db, query_db, insert_db, update_db
import os

conn = connect_db()


def search_all_domain_names():
    sql = "select domain from domain2ip"
    res = query_db(conn, sql)
    for item in res:
        print(item[0])


def get_one_url_page(url, domain_name):
    # 打开浏览器
    driver = webdriver.Firefox()
    # driver.set_window_size(100, 100)
    driver.get(url)  # driver.page_source可以获取当前源码，用BeautifulSoup解析网页
    page = BeautifulSoup(driver.page_source, 'html5lib')
    res_dict = search(page, domain_name)
    driver.get(url)
    time.sleep(2)
    driver.close()
    return res_dict


def get_many_pages():
    raw_url = "https://whois.chinaz.com/"
    sql = "select domain from domain2ip"
    res = query_db(conn, sql)
    i = 0
    res_dict_list = []
    for item in res:
        i += 1
        domain_name = item[0]
        url = raw_url + domain_name
        print('url: {0}'.format(url))
        try:
            res_dict = get_one_url_page(url, domain_name)
            if res_dict:
                res_dict_list.append(res_dict)
            if i % 10 == 0 and len(res_dict_list) > 0:
                save_to_database(res_dict_list)
                res_dict_list = []
        except Exception as e:
            print('get domain {0} error: {1}'.format(domain_name, e))


def get_fields_from_dict(res_dict):
    register_mer = res_dict["注册商"]
    contact_mail = res_dict["联系邮箱"]
    start_time = res_dict["创建时间"]
    expire_time = res_dict["过期时间"]
    domain_server = res_dict["域名服务器"]
    dns = res_dict["DNS"]
    domain_name = res_dict["域名"]
    queryed_domain_name = res_dict["查询域名"]  # 向浏览器查询的域名
    return register_mer, contact_mail, start_time, expire_time, domain_server, dns, domain_name, queryed_domain_name


def save_to_database(res_dict_list):
    sql = ''
    table_name = 'whois_domain'
    for i in range(len(res_dict_list)):
        res_dict = res_dict_list[i]
        register_mer, contact_mail, start_time, expire_time, domain_server, dns, domain_name, queryed_domain_name = get_fields_from_dict(
            res_dict)
        if i == 0:
            sql += 'insert into {0} (queryed_domain_name, domain_name, start_time, expire_time, dns, domain_server, ' \
                   'contact_mail, register_mer) VALUES ("{1}", "{2}","{3}", "{4}", "{5}", "{6}", "{7}", "{8}")'.format(
                table_name, queryed_domain_name, domain_name, start_time, expire_time, dns, domain_server, contact_mail,
                register_mer)
        else:
            sql += ',("{0}", "{1}","{2}", "{3}", "{4}", "{5}","{6}","{7}")'.format(
                queryed_domain_name, domain_name, start_time, expire_time, dns, domain_server, contact_mail,
                register_mer)
    print('sql: {0}'.format(sql))
    insert_db(conn, sql)


def search(page, domain_name):
    class_value1 = 'WhLeList-left'
    class_value2 = 'WhLeList-right'
    tag_value = 'div'
    res1 = page.find_all(tag_value, class_value1)  # <class 'bs4.element.ResultSet'>
    res2 = page.find_all(tag_value, class_value2)  # <class 'bs4.element.ResultSet'>
    res_dict = {"查询域名": domain_name}
    i = 0
    for item in zip(res1, res2):
        div_left = item[0]
        div_right = item[1]
        i += 1

        # print('i: {0}, item: {1}'.format(i, item))
        left_field = div_left.string
        if left_field == '域名':
            # right_value = div_right.contents
            right_value = div_right.contents[1].contents[0].string
            # print('i==1: left_field: {0}， right_value: {1}'.format(left_field, right_value))
        elif left_field == "域名服务器":  # 域名服务器
            right_value = div_right.contents[0].string
            # print('i==7: left_field: {0}, right_value: {1}'.format(left_field, right_value))
        elif left_field == "DNS":  # DNS
            right_value_list = div_right.contents
            right_value = ""
            for j in range(len(right_value_list)):
                print(right_value_list[j])
                if j % 2 == 0:
                    if j != 0:
                        right_value += "," + right_value_list[j]
                    else:
                        right_value += right_value_list[j]
            # print('i==8: left_field: {0}, right_value: {1}'.format(left_field, right_value))
        elif left_field == "创建时间" or left_field == "过期时间" or left_field == "注册商" or left_field == "联系邮箱" or left_field == "联系电话":
            right_value = div_right.contents[0].string
        else:
            continue
        # print('i= {2}, left_field: {0}, right_value: {1}'.format(left_field, right_value, i))
        res_dict[left_field] = right_value
    print('res_dict_list: {0}'.format(res_dict))
    if len(res_dict) > 1:
        return res_dict
    return None


if __name__ == '__main__':
    get_many_pages()
