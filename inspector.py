#!/usr/bin/env python3.7

import boto3
import datetime
import json
from collections import defaultdict

##### setting last monday date and specifying 23h time##############
today = datetime.date.today()
last_monday = (today - datetime.timedelta(days=today.weekday()))

if today == last_monday:
    last_monday = (last_monday - datetime.timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
else:
    last_monday = last_monday.strftime('%Y-%m-%d %H:%M:%S')

last_monday_23 = datetime.datetime.strptime(last_monday, '%Y-%m-%d %H:%M:%S').replace(hour=23)

client = boto3.client('inspector')

def assessment_template():
    response = client.list_assessment_templates(
        filter={
            'namePattern': 'KPMGSecurityInspectorAssessmentTemplate'
        }
    )
    return response['assessmentTemplateArns']


def assessment_runs():
    response = client.list_assessment_runs(
        assessmentTemplateArns = assessment_template(),
        filter={
            'startTimeRange': {
                'beginDate': last_monday_23
            }
        }
    )
    return response['assessmentRunArns']

def assessment_findings():
    paginator = client.get_paginator('list_findings')
    response_iterator = paginator.paginate(
    assessmentRunArns=assessment_runs(),
    filter={
        'severities': ['High']
    },
    PaginationConfig={
        'MaxItems': 500,
        'PageSize': 500,
    })
    for page in response_iterator:
        if page['findingArns'] != []:
            yield page['findingArns']
            
def findings_desc():
    for assessment_findings_to_list in assessment_findings():
        if len(assessment_findings_to_list) > 1:
            for findings in assessment_findings_to_list:
                response = client.describe_findings(
                    findingArns=[
                        findings
                    ]
                )
                yield response['findings']
        else:
            for findings in assessment_findings_to_list: 
                response = client.describe_findings(
                    findingArns=[
                        findings
                    ]
                )
                yield response['findings']

def instance_list():
    lst = []
    for finding in findings_desc():    
        cve_lst = []
        instances = {}
        finding_attributes = finding[0]['attributes']
        for dic in finding_attributes:
            for k in dic.keys():
                if dic[k] == 'CVE_ID':
                    cve_id = dic['value']
                if dic[k] == 'INSTANCE_ID':
                    instance_id = dic['value']
        cve_lst.append(cve_id)
        cve_lst.append(finding[0]['description'])
        instances[instance_id] = cve_lst
        lst.append(instances) 
    newlist = defaultdict(list)
    for i in lst:
        for k, v in i.items(): 
            newlist[k].append(v)

    return json.dumps(newlist)

print (instance_list())
