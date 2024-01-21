import boto3
from botocore.exceptions import NoCredentialsError

def check_cis_benchmarks():
    """
    Check AWS CIS benchmarks for security best practices.
    """
    try:
        # Create an EC2 client
        ec2_client = boto3.client('ec2')

        # CIS Benchmark: Avoid the use of the "root" account
        check_root_account()

        # CIS Benchmark: Ensure IAM password policy requires at least one uppercase letter
        check_iam_password_policy()

        # CIS Benchmark:  Ensure IAM password policy requires at least one lowercase letter
        check_iam_password_policy_lowercase()

        # CIS Benchmark:  Ensure IAM password policy requires at least one symbol
        check_iam_password_policy_symbol()

        # CIS Benchmark: Ensure IAM password policy requires at least one number
        check_iam_password_policy_number()

        # CIS Benchmark: Ensure IAM password policy requires minimum password length
        check_iam_password_policy_length()



    except NoCredentialsError:
        print("Credentials not available or not valid.")

def check_root_account():
    """
    CIS Benchmark: Avoid the use of the 'root' account.
    """
    try:
        iam_client = boto3.client('iam')
        response = iam_client.get_user(UserName='root')
        print("CIS Benchmark: Avoid the use of the 'root' account: FAILED")
        print("Root account should not be in use.")
    except iam_client.exceptions.NoSuchEntityException:
        print("CIS Benchmark: Avoid the use of the 'root' account: PASSED")
        print("Root account is not in use.")

def check_iam_password_policy():
    """
    CIS Benchmark:Ensure IAM password policy requires at least one uppercase letter.
    """
    try:
        iam_client = boto3.client('iam')
        response = iam_client.get_account_password_policy()
        password_policy = response['PasswordPolicy']

        if password_policy['RequireUppercaseCharacters']:
            print("CIS Benchmark: IAM password policy requires at least one uppercase letter: PASSED")
        else:
            print("CIS Benchmark: IAM password policy requires at least one uppercase letter: FAILED")
            print("IAM password policy should require at least one uppercase letter.")

    except iam_client.exceptions.NoSuchEntityException:
        print("IAM password policy not found. Ensure a password policy is set up.")

def check_iam_password_policy_lowercase():
    """
    CIS Benchmark: Ensure IAM password policy requires at least one lowercase letter.
    """
    try:
        iam_client = boto3.client('iam')
        response = iam_client.get_account_password_policy()
        password_policy = response['PasswordPolicy']

        if password_policy['RequireLowercaseCharacters']:
            print("CIS Benchmark: IAM password policy requires at least one lowercase letter: PASSED")
        else:
            print("CIS Benchmark: IAM password policy requires at least one lowercase letter: FAILED")
            print("IAM password policy should require at least one lowercase letter.")

    except iam_client.exceptions.NoSuchEntityException:
        print("IAM password policy not found. Ensure a password policy is set up.")

def check_iam_password_policy_symbol():
    """
    CIS Benchmark: Ensure IAM password policy requires at least one symbol.
    """
    try:
        iam_client = boto3.client('iam')
        response = iam_client.get_account_password_policy()
        password_policy = response['PasswordPolicy']

        if password_policy['RequireSymbols']:
            print("CIS Benchmark: IAM password policy requires at least one symbol: PASSED")
        else:
            print("CIS Benchmark: IAM password policy requires at least one symbol: FAILED")
            print("IAM password policy should require at least one symbol.")

    except iam_client.exceptions.NoSuchEntityException:
        print("IAM password policy not found. Ensure a password policy is set up.")

def check_iam_password_policy_number():
    """
    CIS Benchmark: Ensure IAM password policy requires at least one number.
    """
    try:
        iam_client = boto3.client('iam')
        response = iam_client.get_account_password_policy()
        password_policy = response['PasswordPolicy']

        if password_policy['RequireNumbers']:
            print("CIS Benchmark: IAM password policy requires at least one number: PASSED")
        else:
            print("CIS Benchmark: IAM password policy requires at least one number: FAILED")
            print("IAM password policy should require at least one number.")

    except iam_client.exceptions.NoSuchEntityException:
        print("IAM password policy not found. Ensure a password policy is set up.")

def check_iam_password_policy_length():
    """
    CIS Benchmark: Ensure IAM password policy requires minimum password length.
    """
    try:
        iam_client = boto3.client('iam')
        response = iam_client.get_account_password_policy()
        password_policy = response['PasswordPolicy']

        min_password_length = 14  # Adjust the minimum password length as needed

        if password_policy['MinimumPasswordLength'] >= min_password_length:
            print(f"CIS Benchmark: IAM password policy requires minimum password length of {min_password_length} or more: PASSED")
        else:
            print(f"CIS Benchmark: IAM password policy requires minimum password length of {min_password_length} or more: FAILED")
            print(f"IAM password policy should require a minimum password length of {min_password_length} or more.")

    except iam_client.exceptions.NoSuchEntityException:
        print("IAM password policy not found. Ensure a password policy is set up.")


def check_aws_security_best_practices():
    """
    Check AWS security best practices using Boto3.
    """
    try:
        # Create an EC2 client
        ec2_client = boto3.client('ec2')

        # AWS Best Practice: Ensure all unused IAM credentials are removed
        check_unused_iam_credentials()

        # AWS Best Practice: Ensure CloudTrail is enabled in all regions
        check_cloudtrail_enabled()

        # AWS Best Practice: Ensure AWS Config is enabled
        check_aws_config_enabled()

        # AWS Best Practice: Ensure S3 bucket access logging is enabled
        check_s3_bucket_logging()

        # AWS Best Practice: Ensure security groups follow the principle of least privilege
        check_security_groups_least_privilege()

        # AWS Best Practice: Ensure IAM users have individual credentials
        check_iam_users_individual_credentials()

        # AWS CIS Benchmark: EC2.8 - Ensure EC2 instances are not configured with public IP addresses
        check_ec2_public_ip()

        # Add more checks based on your specific security policies

    except NoCredentialsError:
        print("Credentials not available or not valid.")

def check_unused_iam_credentials():
    """
    AWS Best Practice: Ensure all unused IAM credentials are removed
    """
    try:
        iam_client = boto3.client('iam')
        response = iam_client.list_users()

        for user in response['Users']:
            user_name = user['UserName']
            access_keys = iam_client.list_access_keys(UserName=user_name)['AccessKeyMetadata']

            for key in access_keys:
                if not key['Status'] == 'Active':
                    print(f"AWS Best Practice: Unused IAM credential found for user '{user_name}': FAILED")
                    print("Remove unused IAM credentials.")
                else:
                    print(f"AWS Best Practice: Unused IAM credential check for user '{user_name}': PASSED")

    except Exception as e:
        print(f"Error checking unused IAM credentials: {str(e)}")

def check_cloudtrail_enabled():
    """
    AWS Best Practice: Ensure CloudTrail is enabled in all regions
    """
    try:
        cloudtrail_client = boto3.client('cloudtrail')
        response = cloudtrail_client.describe_trails()

        for trail in response['trailList']:
            if not trail['IsMultiRegionTrail']:
                print(f"AWS Best Practice: CloudTrail is not enabled in all regions: FAILED")
                print("Enable CloudTrail in all regions.")
                return

        print("AWS Best Practice: CloudTrail is enabled in all regions: PASSED")

    except Exception as e:
        print(f"Error checking CloudTrail status: {str(e)}")

def check_aws_config_enabled():
    """
    AWS Best Practice: Ensure AWS Config is enabled
    """
    try:
        config_client = boto3.client('config')
        response = config_client.describe_configuration_recorder_status()

        for recorder_status in response['ConfigurationRecordersStatus']:
            if recorder_status['recording'] != True:
                print("AWS Best Practice: AWS Config is not enabled: FAILED")
                print("Enable AWS Config.")
                return

        print("AWS Best Practice: AWS Config is enabled: PASSED")

    except Exception as e:
        print(f"Error checking AWS Config status: {str(e)}")

def check_s3_bucket_logging():
    """
    AWS Best Practice: Ensure S3 bucket access logging is enabled
    """
    try:
        s3_client = boto3.client('s3')
        buckets = s3_client.list_buckets()['Buckets']

        for bucket in buckets:
            bucket_name = bucket['Name']
            logging = s3_client.get_bucket_logging(Bucket=bucket_name)

            if 'LoggingEnabled' not in logging:
                print(f"AWS Best Practice: S3 bucket '{bucket_name}' does not have access logging enabled: FAILED")
                print("Enable access logging for S3 buckets.")
            else:
                print(f"AWS Best Practice: S3 bucket '{bucket_name}' has access logging enabled: PASSED")

    except Exception as e:
        print(f"Error checking S3 bucket access logging: {str(e)}")

def check_security_groups_least_privilege():
    """
    AWS Best Practice: Ensure security groups follow the principle of least privilege
    """
    try:
        ec2_client = boto3.client('ec2')
        response = ec2_client.describe_security_groups()

        for security_group in response['SecurityGroups']:
            for rule in security_group['IpPermissions']:
                if rule['IpProtocol'] == '-1' or rule['IpRanges'] == [{'CidrIp': '0.0.0.0/0'}]:
                    print(f"AWS Best Practice: Security group '{security_group['GroupName']}' allows unrestricted access: FAILED")
                    print("Review and restrict security group rules.")
                    break
            else:
                print(f"AWS Best Practice: Security group '{security_group['GroupName']}' follows the principle of least privilege: PASSED")

    except Exception as e:
        print(f"Error checking security groups: {str(e)}")

def check_iam_users_individual_credentials():
    """
    AWS Best Practice: Ensure IAM users have individual credentials
    """
    try:
        iam_client = boto3.client('iam')
        response = iam_client.list_users()

        for user in response['Users']:
            user_name = user['UserName']
            access_keys = iam_client.list_access_keys(UserName=user_name)['AccessKeyMetadata']

            if len(access_keys) > 1:
                print(f"AWS Best Practice: IAM user '{user_name}' has multiple access keys: FAILED")
                print("Ensure IAM users have individual credentials.")
            else:
                print(f"AWS Best Practice: IAM user '{user_name}' has individual credentials: PASSED")

    except Exception as e:
        print(f"Error checking IAM user credentials: {str(e)}")

def check_ec2_public_ip():
    """
    AWS CIS Benchmark: EC2.8 - Ensure EC2 instances are not configured with public IP addresses
    """
    try:
        ec2_client = boto3.client('ec2')
        response = ec2_client.describe_instances()

        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                if 'PublicIpAddress' in instance:
                    print(f"AWS CIS Benchmark: EC2.8 - EC2 instance '{instance['InstanceId']}' is configured with a public IP address: FAILED")
                    print("Avoid configuring EC2 instances with public IP addresses.")
                else:
                    print(f"AWS CIS Benchmark: EC2.8 - EC2 instance '{instance['InstanceId']}' is not configured with a public IP address: PASSED")

    except Exception as e:
        print(f"Error checking EC2 instances: {str(e)}")


if __name__ == "__main__":
    check_cis_benchmarks()
    check_aws_security_best_practices()
    # similarly we can add more checks for other services or benchmarks
