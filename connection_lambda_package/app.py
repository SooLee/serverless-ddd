import requests
import logging
import boto3
import uuid
import os
import time


def app(event, context):
    logging.warning("starts logging")
    logging.warning("event= " + str(event))
    logging.warning("context= " + str(context))
    logging.warning("ends logging")

    serverURL = 'http://' + os.environ.get('SERVER_PRIVATE_IP')
    dynamoDB_table = os.environ.get('RAW_TABLE')

    # get resource path
    path = event.get('path', '')
    
    # add requestTime, sourceIP and userAgent to dynamoDB
    requestTime = event.get('requestContext', {}).get('requestTime', '')
    sourceIP = event.get('requestContext', {}).get('identity', {}).get('sourceIp', '')
    userAgent = event.get('requestContext', {}).get('identity', {}).get('userAgent', '')
    dd = boto3.client('dynamodb')
    try:
        dd.put_item(TableName=dynamoDB_table,
                    Item={'uuid': {'S': str(uuid.uuid4())},
                          'sourceIP': {'S': sourceIP},
                          'userAgent': {'S': userAgent},
                          'requestTime': {'S': requestTime},
                          'expdate': {'N': str(int(time.time()) + 3600 * 24)}})  # expires in 24 hrs
    except Exception as e:
        logging.error("Cannot put item to DynamoDB table %s: %s" % (dynamoDB_table, str(e)))
    
    # pass the request to the EC2 server and return the response
    request_headers = event.get('headers', {})
    try:
        res = requests.get(serverURL + path, headers=request_headers)
    except Exception as e:
        print(str(e))
        response = {"statusCode": 404,
                    "headers": {"Content-Type": "text/html"},
                    "body": 'Error: Requested page not found',
                    "multiValueHeaders": {},
                    "isBase64Encoded": False}
        return response
    response = {"statusCode": res.status_code,
                "headers": {"Content-Type": res.headers['Content-Type']},
                "body": res.content.decode('utf-8'),
                "multiValueHeaders": {},
                "isBase64Encoded": False}
    return response
