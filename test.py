from check import get_pdnsip
from check import test_mdns
import pydig

# for pdnsip in get_pdnsip():
#     print(test_pdns(pdnsip))
mdns_list=["129.226.183.76","18.166.93.135","18.162.220.163","3.1.41.69","107.22.242.240","177.71.134.150","20.205.129.40","20.205.128.147","103.90.220.6","103.151.240.71"]
for ip in mdns_list:
    result_mdns=test_mdns(ip)
    print(result_mdns)
    if result_mdns == "Error" or len(result_mdns) == 0 :
        print("bosco")