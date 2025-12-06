#!/usr/bin/env python3
import sys
import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# --- CẤU HÌNH ---
# Thay đổi IP dưới đây thành IP máy chủ MISP của bạn
MISP_BASE_URL = "https://192.168.159.128:8443"
# Dán API Key bạn vừa lấy ở Phần 1
MISP_API_KEY = "peIZsyLiIG0AO9jqI5Z5t5QQfL2Jgfbxa8sPk19f"

# Tắt cảnh báo SSL nếu dùng IP hoặc Self-signed cert
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def query_misp(ioc_type, ioc_value):
    headers = {
        'Authorization': MISP_API_KEY,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    data = {
        "returnFormat": "json",
        "type": ioc_type,
        "value": ioc_value
    }
    try:
        # Endpoint search của MISP
        url = f"{MISP_BASE_URL}/attributes/restSearch"
        response = requests.post(url, headers=headers, json=data, verify=False, timeout=5)
        res_json = response.json()
        
        # Kiểm tra xem có Attribute nào trả về không
        if res_json.get("response", {}).get("Attribute"):
            return res_json["response"]["Attribute"]
        return None
    except Exception as e:
        # Ghi log lỗi nếu cần thiết (debug)
        return None

# Đọc dữ liệu alert từ Wazuh
try:
    alert_file = open(sys.argv[1])
    alert_json = json.loads(alert_file.read())
    alert_file.close()
except Exception:
    sys.exit(1)

# Logic lấy IOC từ Alert của Wazuh
ioc_list = {}

# 1. Lấy Hash từ Syscheck (FIM)
if 'syscheck' in alert_json:
    if 'md5_after' in alert_json['syscheck']:
        ioc_list['md5'] = alert_json['syscheck']['md5_after']
    if 'sha256_after' in alert_json['syscheck']:
        ioc_list['sha256'] = alert_json['syscheck']['sha256_after']

# 2. Lấy IP nguồn từ các log mạng (nếu có)
if 'srcip' in alert_json:
    ioc_list['ip-src'] = alert_json['srcip']

# Thực hiện Query
misp_match = False
misp_details = []

for i_type, i_value in ioc_list.items():
    result = query_misp(i_type, i_value)
    if result:
        misp_match = True
        # Lấy thông tin sự kiện đầu tiên tìm thấy để làm bằng chứng
        event_info = {
            "type": i_type,
            "value": i_value,
            "event_id": result[0].get("event_id"),
            "category": result[0].get("category"),
            "comment": result[0].get("comment")
        }
        misp_details.append(event_info)

# Nếu có Match, gửi Alert mới về Wazuh
if misp_match:
    alert_output = {}
    alert_output["misp_detection"] = misp_details
    alert_output["integration"] = "custom-misp"
    alert_output["description"] = "IOC found in MISP Database"
    
    # Gửi output vào socket của Wazuh để tạo alert mới
    # In ra JSON là cách chuẩn nhất cho custom integration
    print(json.dumps(alert_output))

sys.exit(0)