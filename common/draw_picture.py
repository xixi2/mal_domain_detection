import matplotlib.pyplot as plt


def draw_bar(x_data, y_data, color=None):
    """
    :param x_data:
    :param y_data:
    :return:
    """
    plt.bar(x_data, y_data, fc='g')
    # plt.bar([1,2,3,4],[1,2,3,4],fc='r')
    plt.show()


def draw_pie(label_list, lable_counter, colors=None, explode=None):
    """
    画饼图
    :param ttl_list:
    :param ttl_counter_list:
    :return:
    """
    # labels = 'Frogs', 'Hogs', 'Dogs', 'Logs'
    # sizes = [15, 30, 45, 10]

    # colors = ['yellowgreen', 'gold', 'lightskyblue', 'lightcoral', 'blue']
    # explode = (0, 0.1, 0, 0, 0.05)  # only "explode" the 2nd slice (i.e. 'Hogs')
    # explode = (0, 0, 0, 0, 0)  # only "explode" the 2nd slice (i.e. 'Hogs')

    # plt.pie(sizes, explode=explode, labels=labels, colors=colors,
    #         autopct='%1.1f%%', shadow=True, startangle=90)
    plt.pie(lable_counter, explode=explode, labels=label_list, colors=colors,
            autopct='%1.1f%%', shadow=True, startangle=90)
    # Set aspect ratio to be equal so that pie is drawn as a circle.
    plt.axis('equal')

    plt.show()
