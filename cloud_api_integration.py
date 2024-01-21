import boto3

def list_ec2_instances():
    # Create an EC2 client
    ec2 = boto3.client('ec2')

    # Use the describe_instances method to get information about all instances
    response = ec2.describe_instances()

    # Extract and print instance details
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            print(f"Instance ID: {instance['InstanceId']}")
            print(f"State: {instance['State']['Name']}")
            print(f"Public DNS: {instance.get('PublicDnsName', 'N/A')}")
            print(f"Public IP: {instance.get('PublicIpAddress', 'N/A')}")
            print(f"Private IP: {instance.get('PrivateIpAddress', 'N/A')}")
            print("---------------------------")

# list s3 bucket and it's properties
def list_s3_buckets():
    s3 = boto3.client('s3')
    response = s3.list_buckets()

    print("S3 Buckets:")
    for bucket in response['Buckets']:
        bucket_name = bucket['Name']
        print(f"Name: {bucket_name}")
        print(f"Creation Date: {bucket['CreationDate']}")
        
        # Get bucket ACL
        acl_response = s3.get_bucket_acl(Bucket=bucket_name)
        print(f"\nS3 Bucket ACL for {bucket_name}:")
        for grant in acl_response['Grants']:
            print(f"  - {grant['Permission']} permissions for {grant['Grantee']['Type']}: {grant['Grantee'].get('URI', grant['Grantee'].get('ID', grant['Grantee'].get('DisplayName', '')))}")

        # Get bucket properties
        bucket_location = s3.get_bucket_location(Bucket=bucket_name)
        print(f"\nS3 Bucket Properties for {bucket_name}:")
        print(f"  - Region: {bucket_location.get('LocationConstraint', 'us-east-1')}")  # Default to 'us-east-1' if no specific region is set
        
        print("---------------------------")


# list dynamodb tables and it's properties
def list_dynamodb_tables():
    dynamodb = boto3.client('dynamodb')
    response = dynamodb.list_tables()

    print("DynamoDB Tables:")
    for table_name in response['TableNames']:
        print(f"Table Name: {table_name}")

        # Get table description
        table_description = dynamodb.describe_table(TableName=table_name)['Table']

        # Get provisioned throughput
        print("\nProvisioned Throughput:")
        print(f"  - Read Capacity Units: {table_description['ProvisionedThroughput']['ReadCapacityUnits']}")
        print(f"  - Write Capacity Units: {table_description['ProvisionedThroughput']['WriteCapacityUnits']}")

        # Get key schema
        print("\nKey Schema:")
        for key_schema in table_description['KeySchema']:
            print(f"  - AttributeName: {key_schema['AttributeName']}, KeyType: {key_schema['KeyType']}")

        # Get attributes
        print("\nAttributes:")
        for attribute_definition in table_description['AttributeDefinitions']:
            print(f"  - AttributeName: {attribute_definition['AttributeName']}, AttributeType: {attribute_definition['AttributeType']}")

        # Get encryption information
        print("\nEncryption:")
        if 'SSEDescription' in table_description:
            sse_description = table_description['SSEDescription']
            print(f"  - Status: {sse_description['Status']}")
            print(f"  - Algorithm: {sse_description['SSEAlgorithm']}")
        else:
            print("  - No encryption configured")

        # Get backup information
        print("\nBackup Settings:")
        if 'BackupDescription' in table_description:
            backup_description = table_description['BackupDescription']
            print(f"  - Backup Status: {backup_description['BackupDetails']['BackupStatus']}")
            print(f"  - Last Backup Time: {backup_description['BackupDetails']['BackupStartTime']}")
        else:
            print("  - No backup configured")

        print("---------------------------")


# list rds instances and it's properties
def list_rds_instances():
    rds = boto3.client('rds')
    response = rds.describe_db_instances()

    print("RDS Instances:")
    for db_instance in response['DBInstances']:
        print(f"DB Instance Identifier: {db_instance['DBInstanceIdentifier']}")
        print(f"DB Instance Class: {db_instance['DBInstanceClass']}")
        print(f"Engine: {db_instance['Engine']}")
        print(f"Endpoint: {db_instance['Endpoint']['Address']}:{db_instance['Endpoint']['Port']}")
        print(f"Storage Type: {db_instance['StorageType']}")
        print(f"Allocated Storage: {db_instance['AllocatedStorage']} GB")

        # Get public accessibility information
        print(f"Publicly Accessible: {db_instance['PubliclyAccessible']}")

        # Get encryption information
        print("\nEncryption:")
        if 'StorageEncrypted' in db_instance and db_instance['StorageEncrypted']:
            print(f"  - Storage is encrypted")
            print(f"  - Encryption Type: {db_instance['KmsKeyId']}")
        else:
            print("  - Storage is not encrypted")

        # Get backup information
        print("\nBackup Settings:")
        print(f"  - Automated Backups: {db_instance['BackupRetentionPeriod']} days retention")
        print(f"  - Latest Restorable Time: {db_instance.get('LatestRestorableTime', 'N/A')}")

        print("---------------------------")
    
# list vpc and it's properties
def list_vpcs():
    """
    List all VPCs in the AWS account.
    """
    try:
        ec2_client = boto3.client('ec2')
        response = ec2_client.describe_vpcs()
        vpcs = response['Vpcs']
        # return vpcs
    except Exception as e:
        print(f"Error listing VPCs: {str(e)}")
        return None
    if vpcs:
        print("VPC Properties:")
        for vpc in vpcs:
            print(f"VPC ID: {vpc['VpcId']}")
            print(f"Tags: {vpc.get('Tags', 'N/A')}")
            print("\n")
    else:
        print("No VPCs found.")


def list_subnets():
    """
    List all subnets in the AWS account.
    """
    try:
        ec2_client = boto3.client('ec2')
        response = ec2_client.describe_subnets()
        subnets = response['Subnets']
        
    except Exception as e:
        print(f"Error listing subnets: {str(e)}")
        return None
    if subnets:
        print("Subnet Properties:")
        for subnet in subnets:
            print(f"Subnet ID: {subnet['SubnetId']}")
            print(f"Tags: {subnet.get('Tags', 'N/A')}")
            print("\n")
    else:
        print("No subnets found.")



def list_nacls():
    """
    List all Network Access Control Lists (NACLs) in the AWS account.
    """
    try:
        ec2_client = boto3.client('ec2')
        response = ec2_client.describe_network_acls()
        nacls = response['NetworkAcls']
        
    except Exception as e:
        print(f"Error listing NACLs: {str(e)}")
        return None
    if nacls:
        print("NACL Properties:")
        for nacl in nacls:
            print(f"NACL ID: {nacl['NetworkAclId']}")
            print(f"Tags: {nacl.get('Tags', 'N/A')}")
            print("\n")
    else:
        print("No NACLs found.")



def list_security_groups():
    """
    List all security groups in the AWS account.
    """
    try:
        ec2_client = boto3.client('ec2')
        response = ec2_client.describe_security_groups()
        security_groups = response['SecurityGroups']
    except Exception as e:
        print(f"Error listing security groups: {str(e)}")
        return None
    if security_groups:
        print("Security Group Properties:")
        for sg in security_groups:
            print(f"Security Group ID: {sg['GroupId']}")
            print(f"Tags: {sg.get('Tags', 'N/A')}")
            print("\n")
    else:
        print("No security groups found.")


if __name__ == "__main__":
    # List EC2 instances
    list_ec2_instances()

    # List s3 buckets and it's properties
    list_s3_buckets()

    # List dynamodb tables and it's properties
    list_dynamodb_tables()

    # List rds instances and it's properties
    list_rds_instances()

    # List vpc and it's properties
    list_vpcs()
    
    # List subnets and it's properties
    subnets = list_subnets()
    
    # list nacls and it's properties
    list_nacls()

    # list security groups and it's properties
    list_security_groups()
