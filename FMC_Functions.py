##########################################################################################################################
def GET_ACP_LIST(IP,USERNAME,PASSWORD):
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
    headers['X-auth-access-token']=auth_token
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
def GET_ACCESSRULE_LIST(IP,USERNAME,PASSWORD,ACCESS_POLICY_ID):
    import json
    import sys
    import requests
    server = "https://"+IP
    username = USERNAME
    password = PASSWORD
    ACP_ID=ACCESS_POLICY_ID
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
    headers['X-auth-access-token']=auth_token
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

## Main program  ##
import json
list1=GET_ACP_LIST("192.168.1.48","javad","P@ssw0rd")
#acp_id=list1[1]['id']


#ACL_LIST=GET_ACCESSRULE_LIST("192.168.1.48","javad","P@ssw0rd",acp_id)
##print(json.dumps(ACL_LIST,sort_keys=True,indent=4, separators=(',', ': ')))
#for item in ACL_LIST['items']:
#    print(item['name']+" ::: "+item['links']['self'] )

