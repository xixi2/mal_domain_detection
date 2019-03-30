import redis
from common.redis_op import Host, Port, db, Key

r = redis.Redis(host=Host, port=Port, db=db)

VER_DOMAIN_URL = "https://www.virustotal.com/vtapi/v2/url/report"
WHOIS_URL = 'https://www.virustotal.com/vtapi/v2/domain/report'

ERROR_SLEEP = 60

API_KEYS = [
    "a2c4c89637e57dc27bdb3048989da16c530c2dfffc4783c62fa95ea936e19d80",  # 1
    # "c7af3b7d6c1a0983f19ebab1bf89a13bde1e3cfaf20ee897987b2caa067c8b65",  # 2
    "7d17c888d65a697d16d3549057f79eb9707ec4e8fe3d9cb2f2062b4889101b68",  # 3
    "a2c4c89637e57dc27bdb3048989da16c530c2dfffc4783c62fa95ea936e19d80",  # 4
    "53b56a8ba1140074a526ac7807d1024ff2b888885c8b007f28a8c36c7811e635",  # 5
    "a83a13ebe621bf2024f767196cecf9a2870e3d59a86368f81187a75d70da4dc1"   # 6
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/17.17134",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36"
]

HEADERS = {
    'User-Agent': "",
    'Connection': 'close',
    "Accept-Encoding": "identity",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
}


def get_proxy_from_redis():
    res = r.smembers(Key)
    for ip in res:
        ip = ip.decode("ascii")
        return ip
