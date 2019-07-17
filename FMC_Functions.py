##########################################################################################################################
def GET_ACP_LIST(IP,TOKEN_ID):
    import json
    import requests
    server = "https://"+IP
    r = None
    headers = {'Content-Type': 'application/json'}
    headers['X-auth-access-token']=TOKEN_ID
    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies"    # param
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1]
    # GET OPERATION
    try:
        r = requests.get(url, headers=headers, verify=False)
        status_code = r.status_code
        resp = r.text
        if (status_code == 200):
            #print("GET successful. Response data --> ")
            json_resp = json.loads(resp)
        else:
            r.raise_for_status()
            print("Error occurred in GET --> "+resp)
    except requests.exceptions.HTTPError as err:
        print ("Error in connection --> "+str(err)) 
    finally:
        if r : r.close()
    return json_resp['items']
##########################################################################################################################
def GET_ACCESSRULE_LIST(IP,TOKEN_ID,ACCESS_POLICY_ID):
    import json
    import sys
    import requests
    server = "https://"+IP
    ACP_ID=ACCESS_POLICY_ID
    r = None
    headers = {'Content-Type': 'application/json'}
    headers['X-auth-access-token']=TOKEN_ID
    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/"+ACP_ID+"/accessrules?limit=1000"    # param
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1]
    # GET OPERATION
    try:
        r = requests.get(url, headers=headers, verify=False)
        status_code = r.status_code
        resp = r.text
        if (status_code == 200):
            #print("GET successful. Response data --> ")
            json_resp = json.loads(resp)
        else:
            r.raise_for_status()
            print("Error occurred in GET --> "+resp)
    except requests.exceptions.HTTPError as err:
        print ("Error in connection --> "+str(err)) 
    finally:
        if r : r.close()
    return json_resp
##########################################################################################################################
def GET_ACCESSRULE_DETAIL(IP,TOKEN_ID,ACCESS_POLICY_ID,RULE_ID):
    import json
    import sys
    import requests
    server = "https://"+IP
    ACP_ID=ACCESS_POLICY_ID
    r = None
    headers = {'Content-Type': 'application/json'}
    headers['X-auth-access-token']=TOKEN_ID
    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/"+ACP_ID+"/accessrules/"+RULE_ID# param
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1]
    # GET OPERATION
    try:
        r = requests.get(url, headers=headers, verify=False)
        status_code = r.status_code
        resp = r.text
        if (status_code == 200):
            #print("GET successful. Response data --> ")
            json_resp = json.loads(resp)
            print(json_resp)
        else:
            r.raise_for_status()
            print("Error occurred in GET --> "+resp)
    except requests.exceptions.HTTPError as err:
        print ("Error in connection --> "+str(err)) 
    finally:
        if r : r.close()
    return json_resp
##########################################################################################
def GET_LOGIN_TOKEN(IP,USERNAME,PASSWORD):
    import json
    import sys
    import requests
    server = "https://"+IP
    username = USERNAME
    password = PASSWORD
    r = None
    headers = {'Content-Type': 'application/json'}
    api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
    auth_url = server + api_auth_path
    try:
        r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
        auth_headers = r.headers
        auth_token = auth_headers.get('X-auth-access-token', default=None)
        if auth_token == None:
            print("auth_token not found. Exiting...")
            sys.exit()
    except Exception as err:
        print ("Error in generating auth token --> "+str(err))
        sys.exit()
    return auth_token
#############################################################################################

## Main program  ##
import json
SERVER_IP="192.168.1.48"
USERNAME="javad"
PASSWORD="P@ssw0rd"
#get list of acp
token=GET_LOGIN_TOKEN(SERVER_IP,USERNAME,PASSWORD)

list1=GET_ACP_LIST(SERVER_IP,token)
ACP_ID=list1[1]['id']

#get list of accessrules in acp
ACL_LIST=GET_ACCESSRULE_LIST(SERVER_IP,token,ACP_ID)
print(json.dumps(ACL_LIST,sort_keys=True,indent=4, separators=(',', ': ')))
for item in ACL_LIST['items']:
    RULE_ID=str(item['id'])
    print("================="+item['name']+"=================")
    #get access rule details
    #print(GET_ACCESSRULE_DETAIL(SERVER_IP,USERNAME,PASSWORD,ACP_ID,RULE_ID))
    print(json.dumps(GET_ACCESSRULE_DETAIL(SERVER_IP,token,ACP_ID,RULE_ID),sort_keys=True,indent=4, separators=(',', ': ')))
    print("==================================================================================")