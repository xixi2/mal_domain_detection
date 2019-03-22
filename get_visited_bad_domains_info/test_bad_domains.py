"""
此文件是为了验证提取出的恶意域名是否真的是恶意的，形成最终的恶意域名数据集
"""
import os
import time
import random
from common.common_domains_op import write2file
from common.common_domains_op import UVER_DOM_DIR, VER_DOM_DIR
from get_visited_bad_domains_info.test_one_domain import scan_url


def find_last_checked_lines(dst_file):
    with open(dst_file) as f_out1:
        last_line = f_out1.readlines()[-1]
    return last_line


def test_domains(file, dst_file, choice=2):
    """
    测试恶意域名是否真的是恶意的,并将恶意域名写入dst_file指定的文件内
    :param file: 源文件，保存等待验证的域名
    :param dst_file: 恶意域名写入的文件
    :param choice: 2表示二级域名，3表示3级域名
    :return:
    """
    print("file: %s, dst_file: %s" % (file, dst_file))

    bad_domains = []
    i = 0
    batch_num = 5  # 批处理写入到文件dst_file中的数量

    try:
        with open(file, "r") as f_out:
            lines = f_out.readlines()
            if os.path.exists(dst_file):
                v_last_line = find_last_checked_lines(dst_file)
                # print("lines[235]: %s" % lines[235])
                pos1 = lines.index(v_last_line)
                if pos1 < len(lines):
                    lines = lines[pos1 + 1:]
            print("there is %s left to be handled" % (len(lines),))

            for line in lines:
                print("==============================================")
                start_time = time.time()
                if len(bad_domains) >= batch_num:
                    print("bad_domains write to file")
                    write2file(dst_file, bad_domains)
                    bad_domains = []

                domain = line.strip("\n")
                bad_flag = scan_url(domain)
                if bad_flag:
                    print("add bad_domain: %s" % domain)
                    bad_domains.append(domain)
                if i & 1:
                    random_num = random.randint(5, 15)
                else:
                    random_num = random.randint(10, 20)
                i = 1 - i
                time.sleep(random_num)
                end_time = time.time()
                cost_time = end_time - start_time
                print("handle: %s,bad_flag: %s, cost_time: %s" % (domain, bad_flag, cost_time))
    except Exception as e:
        print("error: %s" % e)
    finally:
        print("totally %s domains are bad!" % len(bad_domains))
        if bad_domains:
            write2file(dst_file, bad_domains)


def test_domains_list(dir):
    """
    验证指定目录下的所有文件内的所有域名是否恶意
    :param dir:
    :return:
    """
    for file in os.listdir(dir):
        dst_file = VER_DOM_DIR + file
        file = UVER_DOM_DIR + file
        test_domains(file, dst_file)


if __name__ == '__main__':
    test_domains_list(UVER_DOM_DIR)
