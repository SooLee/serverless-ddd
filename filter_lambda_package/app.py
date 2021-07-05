import boto3
import os
import json


def lambda_handler(event, context): 

    BlacklistTableName = os.environ.get('BLACKLIST_TABLE_NAME')
    ConnectionLambdaName = os.environ.get('CONNECTION_LAMBDA_NAME')
    
    # check sourceIP and userAgent against Blacklist dynamoDB table
    sourceIP = event.get('requestContext', {}).get('identity', {}).get('sourceIp', '')
    userAgent = event.get('requestContext', {}).get('identity', {}).get('userAgent', '')
    
    # create a key that represents a combination of sourceIP and userAgent
    sourceIP_userAgent = sourceIP + ':::' + userAgent
    
    # check the key against blacklist
    dd = boto3.client('dynamodb')
    res = dd.query(TableName=BlacklistTableName,
                   AttributesToGet=['key'],
                   KeyConditions={'key': {'AttributeValueList': [{'S': sourceIP_userAgent}],
                                          'ComparisonOperator': 'EQ'}})

    # the key exists in blacklist - respond with Forbidden status
    if res['Count'] != 0:
        return {"statusCode": 403,
                "headers": {"Content-Type": "text/html"},
                "body": 'Error: Forbidden to access requested page',
                "multiValueHeaders": {},
                "isBase64Encoded": False}

    # The key is not on blacklist - proceed
    else:
        try:
            # invoke ConnectionLambda which will connect to the Web server instance
            res = boto3.client('lambda').invoke(FunctionName=ConnectionLambdaName,
                                                InvocationType='RequestResponse',
                                                Payload=json.dumps(event).encode())

            # return the response from ConnectionLambda as it is 
            return json.loads(res['Payload'].read().decode('utf-8'))
        except Exception as e:
            raise(e)
