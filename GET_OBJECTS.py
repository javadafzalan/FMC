from FMC_Functions import GET_ACP_LIST
from FMC_Functions import GET_ACCESSRULE_LIST
from FMC_Functions import GET_ACCESSRULE_DETAIL
from FMC_Functions import GET_AUTH_TOKEN
from FMC_Functions import GET_DOMAIN_UUID
from FMC_Functions import GET_OBJ_NETWORKS
from FMC_Functions import GET_NETWORKS_GROUPS
import time
## Main program  ##
import json
SERVER_IP="SERVER_IP"
USERNAME="SERVER_USERNAME"
PASSWORD="SERVER_PASSWORD"
#Generate Token
token=GET_AUTH_TOKEN(SERVER_IP,USERNAME,PASSWORD)
print(token)
#Get Domain UUID
uuid=GET_DOMAIN_UUID(SERVER_IP,token)[1]
print(uuid)
###########################################################
#Get list of Network Objects
host_list=GET_OBJ_NETWORKS(SERVER_IP,uuid,token,"networkaddresses")
OBJECT_DETAIL_LIST=[]
#create a list of organized objects using json output
for item in host_list["items"]:
    OBJECT_DETAIL_LIST.append({
        "name" : item["name"],
        "type" : item["type"],
        "value" : item["value"],
    })

print("List of Network Objects(JSON Format) : ")
for i in OBJECT_DETAIL_LIST:
    print(i)
###########################################################
#GET networkgroup objects
network_groups=GET_NETWORKS_GROUPS(SERVER_IP,uuid,token)
GROUP_OBJ_DETAIL_LIST=[]
for item in network_groups["items"]:
    if("literals" in item):
        GROUP_OBJ_DETAIL_LIST.append({
        "name" : item["name"],
        "value" : item["literals"],

        })
    if("objects" in item):
        GROUP_OBJ_DETAIL_LIST.append({
        "name" : item["name"],
        "value" : item["objects"],
        
        })
print("List of Network group Objects(JSON Format) : ")
for item in GROUP_OBJ_DETAIL_LIST:
    print(item)
    print("###############")
###########################################################