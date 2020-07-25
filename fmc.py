from FMC_Functions import GET_LOGIN_TOKEN
from FMC_Functions import GET_ACP_LIST
from FMC_Functions import GET_ACCESSRULE_LIST
from FMC_Functions import GET_ACCESSRULE_DETAIL

## Main program  ##
import json
SERVER_IP="192.168.1.48"
USERNAME="admin"
PASSWORD="P@ssw0rd"
#get list of acp
token=GET_LOGIN_TOKEN(SERVER_IP,USERNAME,PASSWORD)

list1=GET_ACP_LIST(SERVER_IP,token)
ACP_ID=list1[1]['id']

#get list of accessrules in acp
ACL_LIST=GET_ACCESSRULE_LIST(SERVER_IP,token,ACP_ID)
for item in ACL_LIST['items']:
    RULE_ID=str(item['id'])
    print("================="+item['name']+"=================")
    #get access rule details
    print(GET_ACCESSRULE_DETAIL(SERVER_IP,token,ACP_ID,RULE_ID))
    #print(json.dumps(GET_ACCESSRULE_DETAIL(SERVER_IP,token,ACP_ID,RULE_ID),sort_keys=True,indent=4, separators=(',', ': ')))
    print("=========================================================")
