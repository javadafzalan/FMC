from FMC_Functions import GET_ACP_LIST
from FMC_Functions import GET_ACCESSRULE_LIST
from FMC_Functions import GET_ACCESSRULE_DETAIL
from FMC_Functions import GET_AUTH_TOKEN
from FMC_Functions import GET_DOMAIN_UUID
from FMC_Functions import GET_OBJ_NETWORKS
import time
## Main program  ##
import json
SERVER_IP="172.16.71.21"
#comment for credentials
##another edit for credentials
#also another comment
USERNAME="admin"
PASSWORD="P@ssw0rd"
#Generate Token
token=GET_AUTH_TOKEN(SERVER_IP,USERNAME,PASSWORD)
print(token)
#Get Domain UUID
uuid=GET_DOMAIN_UUID(SERVER_IP,token)[1]
print(uuid)
#Get list of Network Objects
host_list=GET_OBJ_NETWORKS(SERVER_IP,uuid,token,"networkaddresses")
OBJECT_DETAIL_LIST=[]

#print(json.dumps(host_list["items"],indent=5, separators=(',', ': ')))
#create a list of organized objects using json output
for item in host_list["items"]:
    OBJECT_DETAIL_LIST.append({
        "name" : item["name"],
        "type" : item["type"],
        "value" : item["value"],
    })

for i in OBJECT_DETAIL_LIST:
    print(i)
print(len(OBJECT_DETAIL_LIST))
print("**********************")

