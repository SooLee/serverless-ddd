## Serverless-DDos Detection (Serverless-DDD)

This repository contains Lambda code and CloudFormation templates for a minimal, proof-of-concept serverless DDoS Detection and Prevention system.

Detail in https://www.techrxiv.org/articles/preprint/A_serverless_architecture_for_frequency-based_HTTP_request_filtering_against_distributed_denial-of-service_DDoS_attacks/14912778


Note: The template and code have been tested only in us-east-1.



### Denial List DynamoDB

The Denial List DynamoDB Table must be created first using `cloud_formation_template_deniallist.yaml`.



### Lambda code

The Lambda code is in the three zip files which is the compressed contents of the three lamda code folders `alarm_lambda_package`, `filter_lambda_package` and `connection_lambda_package`.


*In case you want to change the Lambda code* (e.g. change parameters), rezip the contents as below:
```bash
cd alarm_lambda_package
zip -r ../alarm_lambda.zip .
cd ..
```


First upload the lambda code zip files to a lambda code bucket.

```bash
BUCKET_NAME=serverless-ddd-lambda-code  # replace with your bucket name

aws s3 cp alarm_lambda.zip s3://$BUCKET_NAME
aws s3 cp filter_lambda.zip s3://$BUCKET_NAME
aws s3 cp connection_lambda.zip s3://$BUCKET_NAME
```

### CloudFormation template

Use `cloud_formation_template.yaml` to create a CloudFormation stack - but first replace some parameters in this file shown below:

```
  # The following parameters must be changed according to the bucket name and admin's email.
  LambdaCodeBucket:
    Type: String
    Default: serverless-ddd-lambda-code  # replace with your bucket name
  EmailAddress:
    Type: String
    Default: duplexa@gmail.com  # replace with your email address

  InvocationThreshold:
    Type: Number
    Default 10  # replace if you want to change the Connection Lambda invocation threshold (per minute)
  DenialThreshold:
    Type: Number
    Default 12  # replace if you want to change the frequency threshold (per minute) for a requester to be listed on Denial list
```

Note that the template includes the Web Server instance with minimal contents - you would want to replace the Web Server part of the template with the actual Web Server you want to run.


