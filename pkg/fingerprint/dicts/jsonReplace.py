import json

# 读取 eHoleFinger.json 文件
with open('eHoleFinger.json', 'r', encoding="UTF-8") as file:
    data = json.load(file)
print(data)

# 替换所有 "cms" 字段对应的值中的空格为 -
for item in data['fingerprint']:
    if 'cms' in item:
        print(item['cms'])
        item['cms'] = item['cms'].replace(' ', '-')

# 将修改后的数据写回文件，使用 utf-8 编码
with open('eHoleFinger.json', 'w', encoding='utf-8') as file:
    json.dump(data, file, indent=4, ensure_ascii=False)
