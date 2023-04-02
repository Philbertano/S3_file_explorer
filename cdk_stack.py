from aws_cdk import (
    Duration,
    Stack,
     aws_sqs as sqs,
     aws_iam as iam,
     aws_s3 as s3,
     aws_cloudfront as cloudfront,
     aws_s3_deployment as s3_deployment,
     aws_cloudfront_origins as origins,
     aws_cognito as cognito
)
from constructs import Construct
import time


#Parameters


# stage dev/qa/prod
stage = "dev" 
#bucket name
BucketName= "agyLogs"
# transistion time to Standard-IA
transitionsTimeToSIA= 30
# transistion time to Glacier
transitionsTimeToGLC= 365
# time to delete the file
expirationTime= 5479



class CdkStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)


        if stage =="dev":            
            # create the S3 bucket for DEV environment
            my_bucket = s3.Bucket(self, BucketName,
                block_public_access=s3.BlockPublicAccess.BLOCK_ALL, 
                object_lock_enabled= True, 
                lifecycle_rules= [
                    s3.LifecycleRule(
                        transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.INFREQUENT_ACCESS,
                            transition_after=Duration.days(transitionsTimeToSIA)
                        ),
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=Duration.days(transitionsTimeToGLC)
                        )],
                    )
                ],
                object_lock_default_retention=s3.ObjectLockRetention.governance(Duration.days(1))
            )

        elif stage=="qa":
            # create the S3 bucket for QA environment
            my_bucket = s3.Bucket(self, BucketName,
                block_public_access=s3.BlockPublicAccess.BLOCK_ALL, 
                object_lock_enabled= True, 
                lifecycle_rules= [
                    s3.LifecycleRule(
                        transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.INFREQUENT_ACCESS,
                            transition_after=Duration.days(transitionsTimeToSIA)
                        ),
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=Duration.days(transitionsTimeToGLC)
                        )],
                object_lock_default_retention=s3.ObjectLockRetention.governance(Duration.days(1))
                    )
                ]
            )
        else:            
            # create the S3 bucket for PROD environment
            my_bucket = s3.Bucket(self, BucketName,
                block_public_access=s3.BlockPublicAccess.BLOCK_ALL, 
                object_lock_enabled= True, 
                lifecycle_rules= [
                    s3.LifecycleRule(
                        transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.INFREQUENT_ACCESS,
                            transition_after=Duration.days(transitionsTimeToSIA)
                        ),
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=Duration.days(transitionsTimeToGLC)
                        )],

                object_lock_default_retention=s3.ObjectLockRetention.compliance(Duration.days(expirationTime))
                    )
                ]
            )

        #role = iam.Role(self, "role", assumed_by= iam.ServicePrincipal("s3.amazonaws.com"))
        # create the bucket policy
        # the role which can write
        my_bucket.add_to_resource_policy(
        iam.PolicyStatement(
            actions=["s3:PutOjbect","s3:GetObject"],
            principals=[iam.AccountPrincipal("ADMIN-USER-ID")],
            resources=[my_bucket.arn_for_objects("*")],
            effect=iam.Effect.ALLOW
                )
            )
        # the read-only policy
        my_bucket.add_to_resource_policy(
        iam.PolicyStatement(
            actions=["s3:GetObject"],
            principals=[iam.AccountPrincipal("ADMIN-USER-ID")],
            resources=[my_bucket.arn_for_objects("*")],
            effect=iam.Effect.ALLOW
                )
            )
'''


       # Create a Distribution with a custom domain name and a minimum protocol version.
# my_bucket: s3.Bucket


        webhost = s3.Bucket(
            self,
            id="mybucket",
            public_read_access=True,
            website_index_document="cdk/HTML/index.html"
            )

        cloudfront.Distribution(self, "frontend",
        default_behavior=cloudfront.BehaviorOptions(origin=origins.S3Origin(webhost)),
        #domain_names=["www.example.com"],
        minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2016,
        ssl_support_method=cloudfront.SSLMethod.SNI
        )

        pool = cognito.UserPool(self, "Pool",
        standard_attributes=cognito.StandardAttributes(
        fullname=cognito.StandardAttribute(
            required=True,
            mutable=False
        ),
        address=cognito.StandardAttribute(
            required=False,
            mutable=True
        )
    ),
        custom_attributes={
            "myappid": cognito.StringAttribute(min_len=5, max_len=15, mutable=False),
            "callingcode": cognito.NumberAttribute(min=1, max=3, mutable=True),
            "isEmployee": cognito.BooleanAttribute(mutable=True),
            "joinedOn": cognito.DateTimeAttribute()
    }
    )
        pool.add_client("app-client",
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(
                    authorization_code_grant=True
                ),
                scopes=[cognito.OAuthScope.OPENID],
                callback_urls=["https://my-app-domain.com/welcome"],
                logout_urls=["https://my-app-domain.com/signin"]
            )
        )

'''