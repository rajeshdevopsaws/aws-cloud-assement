### AWS Cloud Assement

## Introduction

There are two parts to this project. The first part is to query the AWS APIs to get the list of resources. The second part is to assess the security posture of the AWS environment. Especially checking the benchmark standards such as CIS, PCI, HIPAA, etc.

This project is written in Python  and uses boto3 library to query the AWS APIs.

## Prerequisites

1. Python 
2. boto3 library
3. AWS account 

## Installation

1. Install Python
2. Install boto3 library
3. Configure AWS credentials to the local machine

## Usage

1. Clone the repository
```bash
git clone https://github.com/rajeshdevopsaws/aws-cloud-assement.git
```
2. Run the python script to query the AWS APIs.

This will query the AWS APIs and generate the output in the console.
```bash
python3 cloud_assessment.py
```

The same output is referenced in the  cloud-api-results.png

![Cloud API Assessment Results](https://github.com/rajeshdevopsaws/aws-cloud-assement/-/raw/main/cloud-api-results.png)

3. Run the python script to assess the security posture of the AWS environment.


```bash
python3 configuration_assessment.py
```

In this we have two high level functions. The first one is assess the cis benchmarks and the second one is to assess the aws security best practices.

```python
check_cis_benchmarks()
check_aws_security_best_practices()
```

This is very high level approach to assess the security posture of the AWS environment. We can extend this to check the security posture of the AWS environment against the PCI, HIPAA, etc.

We have defined few checks for the CIS benchmarks and AWS security best practices. We can extend this to add more checks.

The same output is referenced in the  cloud-assessment-results.png
![Cloud API Assessment Results](https://github.com/rajeshdevopsaws/aws-cloud-assement/-/raw/main/cloud-assessment-results.png)
### Conclusion
The approach of this project to show the high level approach to assess the security posture of the AWS environment. 

You're not limited to the checks that are defined in this project. You can add more checks to assess the security posture of the AWS environment.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## References

[1] AWS Documentation(https://docs.aws.amazon.com/)
[2] Boto3 Documentation(https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
[3] CIS Benchmarks(https://www.cisecurity.org/benchmark/amazon_web_services/)
[4] AWS Security Hub(https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html)
[5] AWS Security Best Practices(https://docs.aws.amazon.com/whitepapers/latest/aws-overview/security-best-practices.html)

