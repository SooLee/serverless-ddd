import boto3
import logging
import datetime
import os


time_filter_seconds = 600  # look at only events within the past 600 seconds (10 min)
user_info_count_threshold = os.environ.get('DENIAL_LIST_THRESHOLD', 12)  # user who made more than this number of requests is suspicious

BlacklistTableName = os.environ.get('BLACKLIST_TABLE_NAME')
RawTableName = os.environ.get('RAW_TABLE_NAME')
CloudwatchAlarmName = os.environ.get('CLOUDWATCH_ALARM_NAME')

split_str = ':::'  # string used as delimiter to combine sourceIP and userAgent


def lambda_handler(event, context):
    
    # filterin only relevant cloudwatch event
    if event.get('detail', {}).get('alarmName', '') != CloudwatchAlarmName:
        return
    if event.get('detail', {}).get('state', {}).get('value', '') != 'ALARM':
        return

    # scan dynamoDB table
    dd_contents = get_dynamoDB_scan()
    count = dict()

    for entry in dd_contents:
        if time_filter(entry.get('requestTime', '')) is False:
            continue
        if 'sourceIP' in entry and 'userAgent' in entry:
            user_info = entry['sourceIP'] + split_str + entry['userAgent']
            if user_info not in count:
                count[user_info] = 0
            count[user_info] += 1

    # identify suspicious user info (sourceIP + userAgent combination) that made frequent requests
    suspicious = []
    for user_info in count:
        if count[user_info] > user_info_count_threshold:
            sourceIP, userAgent = user_info.split(split_str)
            suspicious.append({'sourceIP': sourceIP,
                               'userAgent': userAgent,
                               'count': count[user_info]})

    # add suspicious user info to denial_list
    for user_info in suspicious:
        add_to_denial_list(user_info)

    # reset the alarm
    #cw = boto3.client('cloudwatch')
    #cw.set_alarm_state(AlarmName=CloudwatchAlarmName, StateValue='OK', StateReason='')
    
    # return the suspicious list
    logging.warning(str({'suspicious': suspicious}))
    return {'suspicious': suspicious}


def add_to_denial_list(user_info):

    # compose key to represent sourceIP and userAgent combination 
    sourceIP_userAgent = user_info['sourceIP'] + split_str + user_info['userAgent']
    
    # just put sourceIP - userAgent combination (primary key) and timestamp
    timestamp = datetime.datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
    print(timestamp)
    dd = boto3.client('dynamodb')
    try:
        dd.put_item(TableName=BlacklistTableName,
                    Item={'key': {'S': sourceIP_userAgent},
                          'timestamp': {'S': timestamp}})
    except Exception as e:
        logging.error("Cannot put item to DynamoDB table %s: %s" % (BlacklistTableName, str(e)))
    

def get_dynamoDB_scan():
    """returns a list of dictionaries 
    {'uuid': <uuid>, 'sourceIP': <sourceIP>, 'userAgent': <userAgent>, 'requestTime': <requestTime>}
    """
    dd = boto3.client('dynamodb')
    entries = []
    start_key = None
    scan_input = {
        'TableName': RawTableName,
        'Select': 'ALL_ATTRIBUTES'
    }
    while(True):
        if start_key:
            scan_input.update({'ExclusiveStartKey': {'uuid': {'S': start_key}}})
        ddres = dd.scan(**scan_input)
        if 'Items' in ddres and len(ddres['Items']) > 0:
            for item in ddres['Items']:
                entries.append({k: v['S'] for k, v in item.items() if k != 'expdate'})
        if 'LastEvaluatedKey' in ddres and ddres['LastEvaluatedKey']:
            start_key = ddres['LastEvaluatedKey']['uuid']['S']
        else:
            break
    return entries


def time_filter(t, seconds=600):
    """Given a time stamp t e.g.'25/Apr/2021:20:58:55 +0000'
    if it is within the past 600 seconds (10 min), return True
    if not return False.
    user can change the number of seconds instead of default 600.
    if the time stamp does not follow the right format,
    returns false
    """
    try:
        t1 = datetime.datetime.strptime(t, "%d/%b/%Y:%H:%M:%S +0000")
    except Exception as e:
        if 'does not match format' in str(e):
            logging.warning("Time stamp '%s' does not match the correct format, skipping..." % t)
        else:
            logging.warning(str(e))
        return False
            
    t2 = datetime.datetime.now()
    td = t2 - t1
    if td.seconds <= seconds:
        return True
    else:
        return False
