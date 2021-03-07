def GET_AUTH_TOKEN(IP,USERNAME,PASSWORD):
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
def GET_DOMAIN_UUID(IP,AUTH_TOKEN):
    import requests
    import json
    # retruns domain-name and domain uuid as a list : ["domain name" , "domain uuid"]
    try:   
        headers = {'Content-Type': 'application/json'}
        server = "https://"+ip
        headers['X-auth-access-token']=auth_token
        api_path = "/api/fmc_platform/v1/info/domain"    # param
        url = server + api_path
        r = requests.get(url, headers=headers, verify=False)
        status_code = r.status_code
        resp = r.text
        if (status_code == 200):
            print("GET successful. Response data --> ")
            json_resp = json.loads(resp)
            domain_uuid=json_resp["items"][0]["uuid"]
            domain_name=json_resp["items"][0]["name"]
            return domain_name,domain_uuid
        else:
            r.raise_for_status()
            print("Error occurred in GET --> "+resp)
    except requests.exceptions.HTTPError as err:
        print ("Error in connection --> "+str(err)) 
    finally:
        if r : r.close()
##########################################################################################################################
def GET_ACP_LIST(IP,DOMAIN_UUID,TOKEN_ID):
    import json
    import requests
    server = "https://"+IP
    r = None
    headers = {'Content-Type': 'application/json'}
    headers['X-auth-access-token']=TOKEN_ID
    api_path = "/api/fmc_config/v1/domain/{}/policy/accesspolicies".format(DOMAIN_UUID)    # param
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
def GET_ACCESSRULE_LIST(IP,DOMAIN_UUID,TOKEN_ID,ACCESS_POLICY_ID):
    import json
    import sys
    import requests
    server = "https://"+IP
    ACP_ID=ACCESS_POLICY_ID
    r = None
    headers = {'Content-Type': 'application/json'}
    headers['X-auth-access-token']=TOKEN_ID
    api_path = "/api/fmc_config/v1/domain/{}/policy/accesspolicies/{}/accessrules?limit=1000".format(DOMAIN_UUID,ACP_ID)    # param
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
def GET_ACCESSRULE_DETAIL(IP,DOMAIN_UUID,TOKEN_ID,ACCESS_POLICY_ID,RULE_ID):
    import json
    import sys
    import requests
    server = "https://"+IP
    ACP_ID=ACCESS_POLICY_ID
    r = None
    headers = {'Content-Type': 'application/json'}
    headers['X-auth-access-token']=TOKEN_ID
    api_path = "/api/fmc_config/v1/domain/{}/policy/accesspolicies/{}/accessrules/{}".format(DOMAIN_UUID,ACP_ID,RULE_ID)# param
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
