"""
这个文件是为了实现对域名字符串的切分和分词
首先利用数字作为分割符将二级域名字符串分割为一个数字列表和一个字符串列表，
然后将字符串列表中的各个字符串使用word_segment方法来进行分词
"""
from wordsegment import segment, load

load()


def is_digit(s):
    if s >= '0' and s <= '9':
        return True
    else:
        return False


def get_longest_meaningful_substring_v0(word_segs):
    longest_len = 0
    longest_substring = ""
    for word_seg in word_segs:
        cur_len = len(word_seg)
        if cur_len > longest_len:
            longest_len = cur_len
            longest_substring = word_seg
    return longest_len, longest_substring


def get_longest_meaningful_substring_v1(word_segs):
    longest_len = 0
    longest_substring_list = []
    for word_seg in word_segs:
        cur_len = len(word_seg)
        if cur_len > 0 and cur_len >= longest_len:
            longest_len = cur_len
            longest_substring_list.append(word_seg)
    return longest_len, longest_substring_list


def get_word_segs(s):
    digit_segs, raw_word_segs = [], []
    l = 0
    start_flag = 0
    start_pos = 0
    end_pos = 0
    n_digits = 0  # 数字字符的数量
    while l < len(s):
        if is_digit(s[l]):
            if not start_flag:
                if not l == 0:
                    word_seg = s[end_pos: l]
                    raw_word_segs.append(word_seg)
                start_flag = 1
                start_pos = l
        else:
            if start_flag:
                end_pos = l
                digit_seg = s[start_pos: end_pos]
                digit_segs.append(digit_seg)
                start_flag = 0
                n_digits += end_pos - start_pos
        l += 1
    if not is_digit(s[len(s) - 1]):
        raw_word_segs.append(s[end_pos:len(s)])
    if start_flag:
        digit_seg = s[start_pos:]
        digit_segs.append(digit_seg)
        n_digits += len(s) - start_pos
    return n_digits, digit_segs, raw_word_segs


def word_segment(s):
    n_digits, digit_segs, raw_word_segs = get_word_segs(s)
    word_segs = []
    for word_seg in raw_word_segs:
        word_seg_list = segment(word_seg)
        word_segs.extend(word_seg_list)
    return n_digits, digit_segs, word_segs


def test():
    # s = "zvi414fvioks63fljd.biz"
    s = "12zvi414fvioks63fljd"
    # s = "zvi414fvioks63fljd.biz12"
    # s = '4chan'
    # s = '9gag'
    # s = "mp4ba"
    # s = "bigass69"
    # s = "zvidsagabardinedazyx"
    # s = "w3schools"
    # n_digits, digit_segs, word_segs = get_word_segs(s)
    s = "isohunt"
    n_digits, digit_segs, word_segs = word_segment(s)
    print('s: {0}'.format(s))
    print(word_segs)
    print(digit_segs)
    print(n_digits)
    print('res: {0}'.format(word_segs))
    longest_len, longest_substring = get_longest_meaningful_substring_v0(word_segs)
    print('longest_len: {0}, longest_substring: {1}'.format(longest_len, longest_substring))

    # new_word_segs = []
    # for item in word_segs:
    #     # print('==============item: {0}============='.format(item))
    #     # print('item: {0}'.format(type(item)))
    #     res = segment(item)
    #     # print('res: {0}'.format(res))
    #     new_word_segs.extend(res)
    # print('res: {0}'.format(new_word_segs))


if __name__ == '__main__':
    load()
    test()

    # s = "mp4ba"
    # res = segment(s)
    # print('res: {0}'.format(res))
