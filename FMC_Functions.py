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
