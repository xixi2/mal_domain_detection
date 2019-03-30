from pymongo import MongoClient

Host = '192.168.105.140'
Port = 27017
User = 'mongo123'
Password = 'mongo123'
database = 'test'

# mongo_url格式： mongodb://[username:password@]hostname[:port][/database]
# mongo_url = 'mongodb://%s:%s@%s:%s/%s' % (User, Password, Host, Port, database)
mongo_url = 'mongodb://%s:%s@%s:%s' % (User, Password, Host, Port)


if __name__ == '__main__':
    client = MongoClient(mongo_url)  # 另一种方式：
    # client = MongoClient(Host, Port)

    # 选择数据库， 方式1，mongo_test是数据库名
    # db = client.mongo_test

    # 方式2
    db_name = "mongo_test"
    db = client[db_name]

    # 在mongodb中添加一个索引test_col，添加一条数据
    # post = {"name":"nancy","age":34}
    # col  = db.test_col
    # col.insert(post)

    # records = db.test_col.find({"name": "google"})  # 结果类型为<class 'pymongo.cursor.Cursor'>，支持for协议，可直接循环取出

    index_name = "test_col"
    records = db[index_name].find({"name": "google"})  # 结果类型为<class 'pymongo.cursor.Cursor'>，支持for协议，可直接循环取出
    print("records: %s" % (records))
    # print(records.count())  # records.count()输出所有结果条数
    # if not records.count():
    #     post = {"name": "google", "age": 31}
    #     col = db.test_col
    #     col.insert(post)

    # db[index_name].update({"name": "acva"}, {"$addToSet": {"weight": 7}, "$inc":{"aage": 1}}, True)
    db[index_name].update({"name": "acdadadd"}, {"$addToSet": {"weight": {"$each": [45]}}}, True)

    # 查询MongoDB数据库mongo_test中的所有索引
    # db_col_names = db.collection_names()
    # print("db_col_name: %s" % db_col_names)

    # 查询索引test_col中的所有记录
    records = db.test_col.find()  # 结果类型为<class 'pymongo.cursor.Cursor'>，支持for协议，可直接循环取出
    print("type: %s ,records: %s" % (type(records), records))
    for item in records:
        print(item)

    # db_name = "malicious_domains"
    # db = client[db_name]
    # # records = db.mal_domains.find()  # 结果类型为<class 'pymongo.cursor.Cursor'>，支持for协议，可直接循环取出
    # records = db["mal_domains"].find()  # 结果类型为<class 'pymongo.cursor.Cursor'>，支持for协议，可直接循环取出
    # print("type: %s ,records: %s" % (type(records), records))
    # print("count: %s" % (records.count()))
    # for item in records:
    #     print(item)
