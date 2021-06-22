# [===============解密base64===============]
# 
# 程序输入：base64加密的字符串
# 程序输出：十六进制字符串

import base64
import sys

test_data = "MIIBUQIBAQQgR04ZBiO41msrTD7RhVm/a5CbCWTbR0ZOzw/Dd6URJlCggeMwgeAC\nAQEwLAYHKoZIzj0BAQIhAP////7/////////////////////AAAAAP//////////\nMEQEIP////7/////////////////////AAAAAP/////////8BCAo6fqenZ9eNE1a\nnkvPZQmn85eJ9RWrj5LdvL1BTZQOkwRBBDLEriwfGYEZX5kERmo5yZSP4wu/8mYL\n4XFaRYkzTHTHvDc2ovT2d5xZvc7ja2khU9Cph3zGKkdAAt8y5SE58KACIQD////+\n////////////////cgPfayHGBStTu/QJOdVBIwIBAaFEA0IABLDD8Q8qaVsdmbL2\nZdQ9CJF4WSL/qyWKnuUL0lpRWYIvnJF28nKGzeP/6T9gI6OyoWhILjFjshxVpwrn\n4c7jQmI="

def ByteToHex(bins):
    return ''.join( [ "%02X" % x for x in bins ] ).strip()

if __name__ == "__main__":

    # if len(sys.argv) < 2:
    #     print("usage : input decode base64 data.")
    #     sys.exit(0)

    bytes_value = base64.b64decode(test_data)
    hexs_value = ByteToHex(bytes_value)
    print (hexs_value)