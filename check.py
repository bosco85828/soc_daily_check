#!/usr/bin/env python3.5.2 # -*- coding:utf-8 -*-

import os
import requests,urllib3
import pydig
import re
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning )

class CustomAdapter ( requests.adapters.HTTPAdapter ): 
    def __init__ ( self , server_hostname , * args , ** kwargs ): 
        self.server_hostname = server_hostname 
        requests.adapters.HTTPAdapter.__init__(self,* args,** kwargs)
    
    def init_poolmanager ( self , * args , ** kwargs ):
        self.poolmanager = requests.adapters.PoolManager( *args , server_hostname = self.server_hostname , **kwargs )  


def get_wafcname():
    ewaf=os.popen("""
    curl "https://docs.google.com/spreadsheets/d/e/2PACX-1vQn3r-rHE-KAVbzVXRMnMXye3QFYc5ntXD0jHiabdYiBrK0p33JNV52QfmYgu8ybxd8fGheQOlTCbE1/pub?gid=1567746631&single=true&output=csv" -Ls | egrep 'prod|globalaccelerator|poc' |egrep -vi 'alhk|hermes'| tr -d '\"' | sort -V | uniq 
    """)

    ewaf_list=[x.strip()+".chinaslb.com" for x in ewaf.readlines()]


    iwaf=os.popen("""
    curl "https://docs.google.com/spreadsheets/d/e/2PACX-1vQn3r-rHE-KAVbzVXRMnMXye3QFYc5ntXD0jHiabdYiBrK0p33JNV52QfmYgu8ybxd8fGheQOlTCbE1/pub?gid=614077665&single=true&output=csv" -Ls | awk -F ',' '$2~"使用"{print $1}'
    """)

    iwaf_list=[x.strip() for x in iwaf.readlines()]
    iwaf_list2=["ansarada.iwaf.jqww33.com","hkddos.iwaf.jqww33.com","hko-iwaf-prod.jqww33.com","noonootv.iwaf.jqww33.com","edgeextension.njhm0832.com","cn2poseidon.common-prod.njhm0832.com"]
    iwaf_list+=iwaf_list2

    return ewaf_list + iwaf_list


def get_wafip(cname):
    resolver=pydig.Resolver(
            executable='/usr/bin/dig',
            nameservers=["8.8.8.8",],
            additional_args=['+time=3',]
            )
    try:
        return resolver.query(cname,'A')
    except:
        pass
    
def test_waf(ip):
    # domain="www.yahoo.com.tw"
    domain = 'test.bentech.site' 
    headers = { 'user-agent' : 'Python 3.x' , 'host' : domain }         

    s = requests.Session () 
    s.mount ( 'https://' + ip + '/' , CustomAdapter ( server_hostname = domain )) #r = s.request('GET', 'https://' + ip + '/', headers=headers, stream=True) 
    
    try:
        r = s.request ( 'GET' , 'https://' + ip + '/?dailycheck' , headers = headers , stream = True)
        return r.status_code
    except:
        return "Error"


def get_pdnsip():
    url="https://docs.google.com/spreadsheets/d/e/2PACX-1vRH4iV54IGHsVRha8A2O2MDSweVbkA4MC2HPpckrxBIu8dfWSlIs52v-4M4VPvXB0q82-Cu-1jeLsMK/pub?gid=1533413977&single=true&output=csv"
    data=requests.get(url)
    result_=re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}',data.text)
    eip_list=list(set([x for x in result_]))
    
    # # f=os.popen("""
    # # curl "https://docs.google.com/spreadsheets/d/e/2PACX-1vRH4iV54IGHsVRha8A2O2MDSweVbkA4MC2HPpckrxBIu8dfWSlIs52v-4M4VPvXB0q82-Cu-1jeLsMK/pub?gid=1533413977&single=true&output=csv" -Ls | awk -F ',' '$1!~"關機" && $1!~"刪除" && $NF!~"IP"{print $NF}'|awk -F ' ' '$1!="\r"{print}'|tr -d "\r"
    # # """)
    # f=os.popen(f"bash {os.getcwd()}/getPDNS.sh")
    # a=f.readlines()
    # pdns_list=[i.strip() for i in a]
    return eip_list

def get_mdnsip():
    mdnsip=os.popen("""
    curl "https://docs.google.com/spreadsheets/d/e/2PACX-1vQn3r-rHE-KAVbzVXRMnMXye3QFYc5ntXD0jHiabdYiBrK0p33JNV52QfmYgu8ybxd8fGheQOlTCbE1/pub?gid=396947093&single=true&output=csv" -Ls | awk -F ',' '$1!~"關機" && $1!~"刪除" && $2!~"stage" && $1!="組別" && $1!="" {print $3}' | tr -d '\r'
    """)

    mdnsip_list=[x.strip() for x in mdnsip.readlines()]
    return mdnsip_list

def test_pdns(ip):
    resolver=pydig.Resolver(
            executable='/usr/bin/dig',
            nameservers=[ip],
            additional_args=['+time=3',]
            )
    cname="pq2tv74b8.cdn2.mlycdn.com"
    
    try:
        return resolver.query(cname,'A')
    except:
        return 'Error'
    # return resolver.query(cname)

def test_mdns(ip):
    resolver=pydig.Resolver(
            executable='/usr/bin/dig',
            nameservers=[ip],
            additional_args=['+time=3',]
            )
    cname="www.willy.com.tw"
    
    try:
        return resolver.query(cname,'A')
    except:
        return 'Error'


def slacksendmsg(msg):
    credentials= "xoxb-201064517493-1900976258641-ZjGfstyjTHS9rlAOth4htBlA"
    oauth_token = credentials
    client=WebClient(token=oauth_token)
    channel_id = 'CRQ9969AL'
    url = 'https://mlytics.slack.com/api/chat.postMessage?'
    headers = { "Authorization": "Bearer " + credentials}
    data = {
                "channel":channel_id,
                "text":f"""
<!subteam^S034F0JKF17>
SOC Daily Check
--------------------------------------------------
{msg}
                """
                }
    requests.post(url,json=data,headers=headers)




if __name__ == "__main__":
    iplist=[]
    cname_list=get_wafcname()
    error_ip=[]
    normal_ip=[]
    # print(cname_list)
    for cname in cname_list:
        list_=get_wafip(cname)
        try:iplist+=list_
        except:pass
    # iplist.append('3.3.3.3')
    for wafip in iplist:
        result_=str(test_waf(wafip))
        # print(wafip,result_)
        if result_ != "200":
            error_ip.append(wafip)
        else : 
            normal_ip.append(wafip)

    error_pdnsip=[]
    normal_pdnsip=[]
    for pdnsip in get_pdnsip():
        result_pdns=test_pdns(pdnsip)
        # print(result_pdns)
        if result_pdns == "Error" or len(result_pdns) == 0 :
            error_pdnsip.append(pdnsip)
        else : 
            normal_pdnsip.append(pdnsip)

    mdns_list=get_mdnsip()
    error_mdnsip=[]
    normal_mdnsip=[]
    for mdnsip in mdns_list:
        result_mdns=test_mdns(mdnsip)
        # print(result_mdns)
        if result_mdns == "Error" or len(result_mdns) == 0 :
            error_mdnsip.append(mdnsip)
        else :
            normal_mdnsip.append(mdnsip)

    msg=f"""
=== WAF_test ===
Correct : {len(normal_ip)}
Error : {error_ip}
=== PDNS_test ===
Correct : {len(normal_pdnsip)}
Error : {error_pdnsip}
=== MDNS_test === 
Correct : {len(normal_mdnsip)}
Error : {error_mdnsip}
"""

    slacksendmsg(msg)    
    # print(msg)
    
    
    