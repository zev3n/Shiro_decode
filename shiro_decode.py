import re
import base64
from Crypto.Cipher import AES

# Author:zev3n 2021.01.16


def b64_padding(data):
    missing_padding = 4 - len(data) % 4
    if missing_padding:
        data += '=' * missing_padding
    return data


def bytesToHexString(bs):
    return ''.join(['%02X' % b for b in bs])


def extract_data(data):
    reg_exp = r"(?:(?:rememberMe=)|(?:^))\b([A-Za-z0-9+\/=]*)(?:;|$|\s)"
    reg_pattern = re.compile(reg_exp)
    try:
        original_value = reg_pattern.search(data).group(1)
        print(data)
        if len(original_value) < 100:
            print('[-]长度过短，请检查您的输入！')
            exit(0)
        decoded_b64 = base64.b64decode(b64_padding(original_value))
    except AttributeError as err:
        raise AttributeError("[-]未识别格式，请检查您的输入！", err)
    except Exception as wtf:
        print("[-]错误：", wtf)
        raise
    return decoded_b64


def brute_decode(keys, data):
    iv = decoded_b64[0:AES.block_size]
    is_find = False
    for b64_key in keys:
        b64_key = b64_key.strip()
        try:
            cipher = AES.new(base64.b64decode(b64_key), AES.MODE_CBC, iv)
        except ValueError:
            continue
        try:
            result = cipher.decrypt(decoded_b64[AES.block_size:])
        except ValueError:
            raise ValueError("输入数据有误")
        if(result.startswith(b'\xac\xed\x00\x05')):
            # print(result)
            is_find = True
            break
    if is_find:
        return b64_key, iv, result
    else:
        print("解密失败")
        exit(0)


def display(choice, key, iv, data):
    print(f"key(base64编码后)：{key}; IV(HexString)：{bytesToHexString(iv)}")
    print("=" * 40)
    if choice == '1' or choice == '':
        print(data)
    elif choice == '2':
        print(re.sub(r'[\x00-\x1f\x7f-\xff\ufffd]',
                     '.', data.decode('ascii', 'replace')))
    elif choice == '3':
        print(bytesToHexString(data))
    elif choice == '4':
        print(base64.b64encode(data).decode())
    else:
        raise ValueError("请输入正确的选项（数字）")


def read_keys(keys_file):
    with open(keys_file, 'r') as rf:
        keys = rf.readlines()
    return keys


if __name__ == '__main__':
    keys_file = 'shiro_keys.txt'
    keys = read_keys(keys_file)
    # print(keys)
    # input_data = """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"""
    input_data = input("请输入Shiro Cookie数据,支持自动提取:\n>")

    decoded_b64 = extract_data(input_data)
    real_key, real_iv, result = brute_decode(
        keys, decoded_b64)  # <bytes> result
    choice = input(
        "请选择输出方式:\n1.默认,将不可见字符转义\n2.将不可见字符替换为[.]\n3.HexString\n4.Base64\n>")
    display(choice, real_key, real_iv, result)
