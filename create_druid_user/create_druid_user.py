#! /usr/bin/env python
# -*- coding: utf-8 -*-
# by Kotov E.
# version: v1.0 01.03.2022
# version: v1.1 03.03.2022
# version: v1.2 25.03.2022
# version: v1.3 17.05.2022

import requests, urllib3
from requests.auth import HTTPBasicAuth
import json
import re,time
import random
import time, os, sys
from datetime import datetime
from random import randrange


#######################################################################################################################
# C O N F I G S
def get_config():
    try:
        with open('druid_add_user.conf.json','r') as conffile:
            return json.load(conffile)
    except Exception as e:
        add_to_log('Error when get config. Error: ' + str(e))
        exit(125)

def set_config(conf):
    try:
        with open('druid_add_user.conf.json','w') as conffile:
            return json.dump(conf,conffile)
    except Exception as e:
        add_to_log('Error when get config. Error: ' + str(e))
        exit(126)

#######################################################################################################################
# L O G S
def add_to_log(datastr,PRINT_LOG_DATA='YES'):
    now = datetime.now()
    now = now.strftime('%Y-%m-%d %H:%M:%S')
    pwd = os.getcwd()
    with open(os.path.join('log', "druid_admin_" + ClusterName + ".log"), "a") as logfile:
        txt = str(now +'\t'+datastr)
        logfile.write(txt + '\n')
        logfile.close()
    # if re.search('.*error.*', datastr, re.IGNORECASE):
    #     add_log_kafka(errorlevel='logdata',
    #                 cluster=stend,
    #                  message=str(datastr))

    if (PRINT_LOG_DATA == 'YES'):
        print(datastr)
    return 0

#######################################################################################################################
# R E Q U E S T S
def getRequest(URL, command):
    try:
        auth=HTTPBasicAuth(druid_admin_conf["druid_admin_user"], druid_admin_conf["druid_admin_pwd"])
        #auth = (druid_role_conf["druid_admin_user"], druid_role_conf["druid_admin_pwd"])
        responce = requests.get(URL + command,
                                auth=auth,
                                timeout=20,
                                verify=False)
        if responce.status_code == 200:
            add_to_log('\tResponse: ' + str(responce.status_code), 'No')
            return True, responce.json()
        else:
            add_to_log('\tResponse error: ' + str(responce.status_code) + '. Error: ' + responce.reason)
            return False, responce.json()['error']
    except Exception as e:
        add_to_log('\tResponse Exception:' + str(e))
        return False, str(e)


def sendRequest(URL, command, json_data=None):
    try:
        auth = HTTPBasicAuth(druid_admin_conf["druid_admin_user"], druid_admin_conf["druid_admin_pwd"])
        responce = requests.post(URL + command,
                                 headers={"Content-Type": "application/json"},
                                 json=json_data,
                                 auth=auth,
                                 timeout=20,
                                 verify=False)
        if responce.status_code == 200:
            add_to_log('\tResponse: ' + str(responce.status_code), 'NO' )  # NO CONTENT # '\t' + str(responce.json()
            return True, 'OK'
        else:
            add_to_log('\tResponse error: ' + str(responce.status_code) + '\t' + + responce.reason)
            return False, str(responce.json())
    except Exception as e:
        add_to_log('\tResponse Exception: ' + str(e), 'NO')
        return False, str(e)

#######################################################################################################################
# U S E R S
def druid_get_users(URL):
    #curl -k  -L --location-trust -u "${DRUIDLP}"   http://${DRUIDHOST}/druid-ext/basic-security/authorization/db/basicAuthorizer/users
    result, data = getRequest(URL, '/druid-ext/basic-security/authorization/db/basicAuthorizer/users')
    add_to_log('Get users: ' + str(data))
    return data

def druid_get_user_details(URL, user, printResult=True):
    resultAuth, dataAuth = getRequest(URL, '/druid-ext/basic-security/authentication/db/basicAuthenticator/users/' + user)
    resultAutr, dataAutr = getRequest(URL, '/druid-ext/basic-security/authorization/db/basicAuthorizer/users/' + user)
    if printResult:
        add_to_log('Get user [' + user + '] from Authenticator: ' + str(dataAuth))
        add_to_log('Get user [' + user + '] from Authorizer: ' + str(dataAutr))
    return resultAuth and resultAutr, dataAuth, dataAutr

def druid_create_user(URL, json_user ):
    #Create user item
    user = json_user['druid_user']
    user_passwd = json_user['druid_pwd']
    resultAuth, dataAuth = sendRequest(URL, '/druid-ext/basic-security/authentication/db/basicAuthenticator/users/' + user)
    add_to_log('Create user [' + user + '] in Authenticator: ' + str(dataAuth))
    resultAutr, dataAutr = sendRequest(URL, '/druid-ext/basic-security/authorization/db/basicAuthorizer/users/' + user)
    add_to_log('Create user ['+user+'] in Authorizer: ' + str(dataAutr))


    #Set user password
    if druid_get_user_details(URL, user, False)[0]:
        druid_set_user_password(URL, user, user_passwd, printResult=True)


    return resultAuth and resultAutr, dataAuth, dataAutr

def druid_set_user_password(URL, user, password, printResult=True):
    user_passwd = {"password": password}
    resultAutr, dataAutr = sendRequest(URL,
                                       '/druid-ext/basic-security/authentication/db/basicAuthenticator/users/' + user + '/credentials',
                                       json_data=user_passwd)
    if printResult:
        add_to_log('Set user [' + user + '] password: ' + str(resultAutr))
    return resultAutr, dataAutr

def druid_assing_user_to_role(URL, user, role):
    if druid_get_role_details(URL, role, False)[0] and druid_get_user_details(URL, user, False)[0]:
        # return result, jsondata
        result, data =  sendRequest(URL, '/druid-ext/basic-security/authorization/db/basicAuthorizer/users/'+user+'/roles/'+role)
        add_to_log('Assing user [' + user + '] to role [' + role + ']: ' + str(data))
        return result, data
    else:
        return  False, ''

#######################################################################################################################
# R O L E S
def druid_get_roles(URL):
    result, data = getRequest(URL, '/druid-ext/basic-security/authorization/db/basicAuthorizer/roles')
    add_to_log('Get all roles: ' + str(data))
    return data

def druid_get_role_details(URL, role, printResult=True):
    result, data =  getRequest(URL, '/druid-ext/basic-security/authorization/db/basicAuthorizer/roles/' + role)
    if printResult:
        add_to_log('Get role ['+role+']: ' + str(data))
    return  result, data

def druid_create_role(URL, json_role):
    #Create role item
    role = json_role['role']
    DataSource = json_role['dataSource']
    Action = json_role['action']
    result, data = sendRequest(URL, '/druid-ext/basic-security/authorization/db/basicAuthorizer/roles/' + role)
    add_to_log('Create role [' + role + '] : ' + str(data))

    #Set Access Rules
    if druid_get_role_details(URL, role, False)[0]:
        AccessRules = [{"resource" : {"name": DataSource, "type":"DATASOURCE"}, "action": Action}]
        result, data = sendRequest(URL,
                                   '/druid-ext/basic-security/authorization/db/basicAuthorizer/roles/' + role + '/permissions',
                                   json_data=AccessRules)
        add_to_log('Set role [' + role + '] access rules: ' + str(data))




#######################################################################################################################
# M E N U
def menu_action_data(json_data):
    for param in json_data:
        #print("Input value for ", clusternamelist,": " , end='')
        usrval = input("Input value for: " + param + " [def: \"" + json_data[param] + "\"]: ")
        if usrval != '':
            json_data[param] = usrval
    return json_data


def menu_select_action(druid_user_conf):
    print("Select action:")
    print("  ## View:")
    for a in actions_list:
        if not re.match('[A-z]',a):
            print("     ", a + ".", actions_list[a])
        else:
            print("     ", actions_list[a])

    params = {}
    action = input('# Action (1): ')
    if action == '':
        action = '1'

    if actions_list[action] == "List users":
        druid_get_users(clusterURL)
    elif actions_list[action] == "List user details":
        user = input(" User name: ")
        if user == '':
            print('User not set.')
        else:
            druid_get_user_details(clusterURL, user)
    elif actions_list[action] == "List roles":
        druid_get_roles(clusterURL)
    elif actions_list[action] == "List roles details":
        role = input(" Role name: ")
        if role == '':
            print('Role not set.')
        else:
            druid_get_role_details(clusterURL, role)
    elif actions_list[action] == "Create user":
        druid_user_conf = menu_action_data(druid_user_conf)
        druid_create_user(clusterURL, druid_user_conf)
    elif actions_list[action] == "Create role":
        druid_user_conf = menu_action_data(druid_role_conf)
        druid_create_role(clusterURL, druid_user_conf)
    elif actions_list[action] == "Assign user to role":
        user = input(" User name: ")
        role = input(" Role name: ")
        if user == '' or role == '':
            print('User/role not set.')
        else:
            druid_assing_user_to_role(clusterURL, user,  role)
    elif actions_list[action] == "Set user password":
        user = input(" User name: ")
        pwd = input(" User password: ")
        if user == '' or pwd == '':
            print('User/pwd not set.')
        else:
            druid_set_user_password(clusterURL, user, pwd)
    elif actions_list[action] == "Exit":
        return 'Exit'

    return 'Action'

########################################################################################################################
# M A I N
########################################################################################################################
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
config = get_config()


ClusterName = 'not_set'
druid_admin_conf = {"druid_admin_user": "admin",
                   "druid_admin_pwd": ""}

druid_user_conf = {"druid_user": "admin",
                   "druid_pwd": ""}

druid_role_conf = {"role": "viewer",
                   "dataSource": ".*",
                   "action": "READ"}

actions_list = {
                   "1": "List users",
                   "2": "List user details",
                   "3": "List roles",
                   "4": "List roles details",
                   "5": "Create user",
                   "6": "Create role",
                   "7": "Assign user to role",
                   "8": "Set user password",
                   "A": "-Delete user",
                   "B": "-Delete role",
                   "0" : "Exit"
                   }


#MENU select ClusterName
if True:
    clusternamelist = ''
    for clustername in config:  clusternamelist += clustername + ' '
    print("Select cluster: ", clusternamelist)
    ClusterName = input('# Cluster ('+clustername+'): ')
    if ClusterName == '':   ClusterName = clustername
#ClusterName = 'PSI_Int' # for tests
clusterURL = config[ClusterName]
print("Input Druid admin user. ")
druid_admin_conf = menu_action_data(druid_admin_conf)

menu_exit = ''
while menu_exit != 'Exit':
    print("Cluster:", ClusterName, "url:", clusterURL)
    print()
    menu_exit = menu_select_action(druid_user_conf)

exit(0)

# curl -u "${DRUIDLP}" -XPOST  http://${DRUIDHOST}/druid-ext/basic-security/authentication/db/basicAuthenticator/users/tengri_monitor
# curl -u "${DRUIDLP}" -XPOST  http://${DRUIDHOST}/druid-ext/basic-security/authorization/db/basicAuthorizer/users/tengri_monitor
# curl -u "${DRUIDLP}" -H'Content-Type: application/json' --data-binary @pass.json  -XPOST  http://${DRUIDHOST}/druid-ext/basic-security/authentication/db/basicAuthenticator/users/${DUSER}/credentials
# curl  -u  "${DRUIDLP}" XPOST  http://${DRUIDHOST}/druid-ext/basic-security/authorization/db/basicAuthorizer/roles/viewer_role
# curl -u "${DRUIDLP}" -H'Content-Type: application/json' --data-binary @role.json  -XPOST  http://${DRUIDHOST}/druid-ext/basic-security/authorization/db/basicAuthorizer/roles/${DROLE}/permissions
# curl -u "${DRUIDLP}" -XPOST  http://${DRUIDHOST}/druid-ext/basic-security/authorization/db/basicAuthorizer/users/${DUSER}/roles/${DROLE}