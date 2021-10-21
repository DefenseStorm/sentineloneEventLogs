#!/usr/bin/env python3

import sys,os,getopt
import traceback
import os
import requests
import re
import datetime
import json

sys.path.insert(0, 'ds-integration')
from DefenseStorm import DefenseStorm

#region API's
API_PATH = 'web/api/v2.0/'
API_SITES = 'web/api/v2.0/sites'
API_STATIC_INDICATORS = 'web/api/v2.0/threats/static-indicators'
API_ACTIVITY_TYPES = 'web/api/v2.0/activities/types'

class integration(object):

    JSON_field_mappings = {
        'accountId': 'account_id',
        'accountName': 'account_name',
        'agentId': 'agent_id',
        'computerName': 'computer_name',
        'deviceName': 'device_name',
        'eventId': 'event_id',
        'eventType': 'event_type',
        'fullScopeDetails': 'details',
        'groupId': 'group_id',
        'groupName': 'group_name',
        'interface': 'nterface',
        'lastLoggedInUserName': 'username',
        'osType': 'os_type',
        'productId': 'product_id',
        'ruleId': 'rule_id',
        'ruleName': 'rule_name',
        'ruleType': 'rule_type',
        'scopeName': 'policy_scope_name',
        'siteName': 'site',
        'vendorId': 'vendor',
        'version': 'version',
        'id': 'id',
        'primaryDescription': 'message',
        'siteId': 'site_id',
        'threatId': 'threat_id',
        'userId': 'user_id',
    }

    def get_site_id(self):
        params = {
            'name': self.ds.config_get('sentinelone', 'site')
            }
        r = requests.get(self.SRC_hostname+API_SITES, headers=self.SRC_headers, params=params)
        if r.status_code != 200:
            #print ('Error: ', r.json())
            self.ds.log('ERROR', r.json())
            sys.exit()
        return r.json()['data']['sites'][0]['id']

    def get_activityTypes(self):
        #print('Loading Activity Type...')
        self.ds.log('INFO', 'Loading Activity Types...')
        r = requests.get(self.SRC_hostname+API_ACTIVITY_TYPES, headers=self.SRC_headers)
        if r.status_code != 200:
            print ('Error: ', r.status_code)
            self.ds.log('ERROR', r.status_code)
            sys.exit()
        jdata = r.json()
        at = {}
        for item in jdata['data']:
            at[item['id']] = {'action': item['action'], 'descriptionTemplate':item['descriptionTemplate']}

        return at


    def get_staticIndicators(self):
        #print('Loading Static Indicators...')
        self.ds.log('INFO', 'Loading Static Indicators...')
        r = requests.get(self.SRC_hostname+API_STATIC_INDICATORS, headers=self.SRC_headers)
        if r.status_code != 200:
            print ('Error: ', r.status_code)
            self.ds.log('ERROR', r.status_code)
            sys.exit()
        raw = r.json()['data']['indicators']
        si = {}
        for tmp in raw:
            if 'categoryId' in tmp.keys():
                cID = tmp['categoryId']
            else:
                cID = ''
            cName = tmp['categoryName']
            descripClean = re.sub('<.*?>', ' ', tmp['description'])
            id = int(tmp['id'])
            si[id] = {'catid': cID, 'catname': cName, 'desc': descripClean}

        return si

    def get_datalist(self,site_id, data_type, lastrun, currentrun):
        datalist = []
        cursor = ''

        while (cursor != None):
            params = {
                'siteIds': site_id,
                'limit': 100,
                'cursor': cursor,
                'createdAt__gte': lastrun,
                'createdAt__lt': currentrun,
            }
            r = requests.get(self.SRC_hostname+API_PATH+data_type, headers=self.SRC_headers, params=params)
            if r.status_code != 200:
                self.ds.log('ERROR', str(r.status_code) + r.text)
                sys.exit('Error while getting datalist, exiting..')
            cursor = r.json()['pagination']['nextCursor']
            datalist.extend(r.json()['data'])
        return datalist

    def parseActivity(self, tmp):
        entry = {}
        if 'data' not in tmp.keys():
            self.ds.log('ERROR', 'Bad activity format: ' + str(tmp))
            return tmp
        for item in tmp.keys():
            if item == 'data':
                for data_item in tmp['data'].keys():
                    if data_item in ['accountName']:
                        continue
                    if data_item in entry.keys():
                        self.ds.log('ERROR', 'Bad activity data format for field ' + data_item + ': ' + str(tmp))
                        return tmp
                    entry[data_item] = tmp['data'][data_item]
            else:
                entry[item] = tmp[item]
            if tmp['activityType'] in self.activityTypes.keys():
                entry['action'] = self.activityTypes[tmp['activityType']]['action']
        return entry


    def parseResponse(self, tmp):
        entry={}
        if tmp['mitigationReport']['network_quarantine']['status'] is None:
            entry['mynetwork_quarantine'] = 'None'
        else:
            entry['mynetwork_quarantine'] = tmp['mitigationReport']['network_quarantine']['status']

        if tmp['mitigationReport']['kill']['status'] is None:
            entry['mitigation_kill'] = 'None'
        else:
            entry['mitigation_kill'] = tmp['mitigationReport']['kill']['status']

        if tmp['mitigationReport']['quarantine']['status'] is None:
            entry['mitigation_quar'] = 'None'
        else:
            entry['mitigation_quar'] = tmp['mitigationReport']['quarantine']['status']

        if tmp['mitigationReport']['remediate']['status'] is None:
            entry['mitigation_rem'] = 'None'
        else:
            entry['mitigation_rem'] = tmp['mitigationReport']['remediate']['status']

        if tmp['mitigationReport']['rollback']['status'] is None:
            entry['mitigation_roll'] = 'None'
        else:
            entry['mitigation_roll'] = tmp['mitigationReport']['rollback']['status']

        # translate indicators (id => description)
        entry['threatIndicators'] = []
        IndicatorIDs = tmp['indicators']
        if len(IndicatorIDs) > 0:
            for i in IndicatorIDs:
                entry['threatIndicators'].append(self.staticIndicators[i]['desc'])
        else:
            entry['threatIndicators'] = 'NI'

        entry['agentComputerName'] = tmp['agentComputerName']
        entry['agentDomain'] = tmp['agentDomain']
        entry['agentId'] =  tmp['agentId']
        entry['agentInfected'] = tmp['agentInfected']
        entry['agentIp'] = tmp['agentIp']
        entry['agentIsActive'] = tmp['agentIsActive']
        entry['agentIsDecommissioned'] = tmp['agentIsDecommissioned']
        entry['agentMachineType'] = tmp['agentMachineType']
        entry['agentNetworkStatus'] = tmp['agentNetworkStatus']
        entry['agentOsType'] = tmp['agentOsType']
        entry['agentVersion'] = tmp['agentVersion']
        entry['annotation'] = tmp['annotation']
        if 'annotationUrl' in tmp.keys():
            entry['annotationUrl'] = tmp['annotationUrl']
        entry['browserType'] = tmp['browserType']
        entry['certId'] = tmp['certId'].encode('utf-8')
        entry['classification'] = tmp['classification']
        entry['classificationSource'] = tmp['classificationSource']
        entry['classifierName'] = tmp['classifierName']
        entry['cloudVerdict'] = tmp['cloudVerdict']
        entry['collectionId'] = tmp['collectionId']
        entry['createdAt'] = tmp['createdAt']
        entry['createdDate'] = tmp['createdDate']
        entry['resolved'] = tmp['resolved']
        entry['description'] =  tmp['description']
        entry['engines'] = tmp['engines']
        entry['fileCreatedDate'] = tmp['fileCreatedDate']
        entry['fileDisplayName'] = tmp['fileDisplayName']
        entry['fileExtensionType'] = tmp['fileExtensionType']
        entry['fileIsDotNet'] = tmp['fileIsDotNet']
        entry['fileIsExecutable'] = tmp['fileIsExecutable']
        entry['fileIsSystem'] = tmp['fileIsSystem']
        entry['fileMaliciousContent'] = tmp['fileMaliciousContent']
        entry['fileObjectId'] = tmp['fileObjectId']
        entry['filePath'] = tmp['filePath']
        entry['fileSha256'] = tmp['fileSha256']
        entry['fileVerificationType'] = tmp['fileVerificationType']
        entry['fromCloud'] = tmp['fromCloud']
        entry['fromScan'] = tmp['fromScan']
        entry['id'] = tmp['id']
        entry['isCertValid'] = tmp['isCertValid']
        entry['isInteractiveSession'] = tmp['isInteractiveSession']
        entry['isPartialStory'] = tmp['isPartialStory']
        entry['maliciousGroupId'] = tmp['maliciousGroupId']
        entry['maliciousProcessArguments'] = tmp['maliciousProcessArguments']
        entry['markedAsBenign'] = tmp['markedAsBenign']
        entry['mitigationMode'] = tmp['mitigationMode']
        entry['accountId'] = tmp['accountId']
        entry['accountName'] = tmp['accountName']
        entry['commandId'] = tmp['commandId']
        entry['fileContentHash'] = tmp['fileContentHash']
        entry['initiatedBy'] = tmp['initiatedBy']
        entry['initiatedByDescription'] = tmp['initiatedByDescription']
        entry['mitigationMode'] = tmp['mitigationMode']
        entry['mitigationStatus'] = tmp['mitigationStatus']
        entry['publisher'] = tmp['publisher'].encode('utf-8')
        entry['rank'] = tmp['rank']
        entry['siteId'] = tmp['siteId']
        entry['siteName'] = tmp['siteName']
        entry['threatAgentVersion'] = tmp['threatAgentVersion']
        entry['threatName'] = tmp['threatName']
        entry['updatedAt'] = tmp['updatedAt']
        entry['username'] = tmp['username']
        entry['whiteningOptions'] = tmp['whiteningOptions']

	# Build the message entry:
        entry['message'] = entry['threatName'] + ': Kill:' + entry['mitigation_kill'] + ', Quarantine:' + entry['mitigation_quar'] + ', Host:' + entry['agentComputerName']

	# Build the compatible timestamp
        entry_time = datetime.datetime.strptime(entry['createdAt'], '%Y-%m-%dT%H:%M:%S.%fZ')
        entry['timestamp'] = entry_time.strftime('%Y-%m-%dT%H:%M:%SZ')

        return entry


    def run(self):
        self.state_dir = self.ds.config_get('sentinelone', 'state_dir')
        last_run = self.ds.get_state(self.state_dir)
        if last_run == None:
            self.ds.log('INFO', 'No datetime found, defaulting to last 12 hours for results')
            last_run = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
        current_run = datetime.datetime.utcnow()

        last_run_str = last_run.strftime('%Y-%m-%dT%H:%M:%SZ')
        current_run_str = current_run.strftime('%Y-%m-%dT%H:%M:%SZ')

        self.site_id = self.get_site_id()
        self.staticIndicators = self.get_staticIndicators()
        self.activityTypes = self.get_activityTypes()
        self.ds.log('INFO', 'From Site: '+self.ds.config_get('sentinelone', 'site')+' [ID: '+ self.site_id +']')


        # What are 'groups', applications for?
        for data_type in ['threats', 'agents', 'activities']:
            self.ds.log('INFO', 'Getting ' + data_type + ' events from: ' + last_run_str + ' to ' + current_run_str)
            data = self.get_datalist(self.site_id, data_type, last_run_str, current_run_str)
            self.ds.log('INFO', 'Received ' + str(len(data)) + ' events for type ' + data_type)

            for item in data:
                try:
                    if data_type == 'threats':
                        parsed_item = self.parseResponse(item)
                    if data_type == 'activities':
                        parsed_item = self.parseActivity(item)
                    else:
                        parsed_item = item
                except Exception as e:
                    self.ds.log('ERROR', 'ERROR: ' + traceback.format_exc().replace('\n', ' '))
                    continue
                parsed_item['category'] = data_type
                self.ds.writeJSONEvent(parsed_item, JSON_field_mappings = self.JSON_field_mappings)

        self.ds.set_state(self.state_dir, current_run)
    
    def usage(self):
        print()
        print(os.path.basename(__file__))
        print()
        print('  No Options: Run a normal cycle')
        print()
        print('  -t    Testing mode.  Do all the work but do not send events to GRID via ')
        print('        syslog Local7.  Instead write the events to file \'output.TIMESTAMP\'')
        print('        in the current directory')
        print()
        print('  -l    Log to stdout instead of syslog Local6')
        print()
    
    def __init__(self, argv):

        self.testing = False
        self.send_syslog = True
        self.ds = None
        self.site_id = None
        self.staticIndicators = None

        self.SRC_headers = None
    
        try:
            opts, args = getopt.getopt(argv,'htnld:',['datedir='])
        except getopt.GetoptError:
            self.usage()
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                self.usage()
                sys.exit()
            elif opt in ('-t'):
                self.testing = True
            elif opt in ('-l'):
                self.send_syslog = False
    
        try:
            self.ds = DefenseStorm('sentineloneEventLogs', testing=self.testing, send_syslog = self.send_syslog)
        except Exception as e:
            traceback.print_exc()
            try:
                self.ds.log('ERROR', 'ERROR: ' + str(e))
            except:
                pass
        try:
            self.SRC_headers = {
                    'Content-type': 'application/json',
                    'Authorization': 'APIToken ' + self.ds.config_get('sentinelone', 'token')
                    }
            self.SRC_hostname = 'https://'+self.ds.config_get('sentinelone', 'console')+'.sentinelone.net/'
        except Exception as e:
            traceback.print_exc()
            try:
                self.ds.log('ERROR', 'ERROR: ' + str(e))
            except:
                pass



if __name__ == '__main__':
    i = integration(sys.argv[1:]) 
    i.run()
