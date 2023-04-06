import boto3
import jwt
import json
import base64
from datetime import datetime, timezone

PROFILE_NAME = "<Your AWS profile name>" # arjstack-training
AWS_ACCOUNT_ID =  "<AWS Account Number>"

KMS_KEY_REGION = "<AWS Region Code where KMS key exist used for sign/verify>" # ap-south-1
KMS_KEY_ALIAS = "<It could be anything based on your choice>" # arjstack-sign

KMS_KEY_USAGE = "SIGN_VERIFY"
KMS_KEY_SPEC = "ECC_NIST_P521"
KMS_SIGNING_ALGO = "ECDSA_SHA_512"

JWT_ALGO = "HS512"

def get_kms_client(region: str):
    """
    Gets KMS Client
    """
    session = boto3.Session(profile_name=PROFILE_NAME)
    kms_client = session.client("kms", region_name=region)
    return kms_client

def create_kms_key(kms_client, key_usage, key_spec, description=None, tags=[]):
    """
    Creates a Customer Managed KMS key for SIGN_VERIFY.
    """
    try:
        response = kms_client.create_key(KeyUsage=key_usage,
                                         CustomerMasterKeySpec=key_spec,
                                         Description=description,
                                         Tags=tags)
        
    except:
        print(f"Error while creating KMS key for {key_usage}")
        raise
    else:
        return response

def attach_kms_key_policy(kms_client, kms_key, root_user_arn, key_admins_arn_list, key_users_arn_list):
    """
    Attach the KMS policy to KMS Key
    """
    policy= dict({
                "Version": "2012-10-17",
                "Id": "key-default-1",
                "Statement": [
                    {
                        "Sid": "Enable IAM policies",
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": root_user_arn
                        },
                        "Action": "kms:*",
                        "Resource": "*"
                    },
                    {
                        "Sid": "Allow access for Key Administrators",
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": key_admins_arn_list
                        },
                        "Action": [
                            "kms:Create*",
                            "kms:Enable*",
                            "kms:Put*",
                            "kms:Update*",
                            "kms:TagResource"
                        ],
                        "Resource": "*"
                    },
                    {
                        "Sid": "Allow use of the key",
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": key_users_arn_list
                        },
                        "Action": [
                            "kms:DescribeKey",
                            "kms:GetPublicKey",
                            "kms:Sign",
                            "kms:Verify"
                        ],
                        "Resource": "*"
                    }]
                } )
    try:
        print("================= Attaching following Key Policy with KMS Key =================\n")
        print(json.dumps(policy))
        kms_client.put_key_policy(KeyId=kms_key, PolicyName='default', Policy=json.dumps(policy))

    except Exception as err:
        print( "Couldn't set policy for key %s. Here's why %s", kms_key, err)
        raise

def create_kms_key_alias(kms_client, key_id, alias_name):
    """
    Creates a Custom name/alias for a KMS key.
    """
    try:
        print(f"\n================= Creating Alias `{alias_name}` for KMS Key `{key_id}` =================\n")
        response = kms_client.create_alias(AliasName=alias_name, TargetKeyId=key_id)
        print(f"Alias `{alias_name}` is created for KMS Key `{key_id}`\n")
    except:
        print(f"Error while creating KMS key alias `{alias_name}` for KMS Key `{key_id}`\n")
        raise
    else:
        return response

def configure_kms_key(kms_client, key_alias):
    """
    Configure KMS Key: Key Crreation, Policy Attachment, Alias Creation 
    """
    tag_env = dict({"TagKey": "Purpose", "TagValue": "Signature"})
    response = create_kms_key(kms_client, KMS_KEY_USAGE, KMS_KEY_SPEC, "KMS Key for E-Signature", [tag_env])
    kms_key_id = response['KeyMetadata']['KeyId']
    print(f"KMS Key `{kms_key_id}` is created.\n")

    # KMS Key Policy
    root_user_arn = f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"
    key_admins_arn_list = ["*"]
    key_users_arn_list = ["*"]

    attach_kms_key_policy(kms_client, kms_key_id, root_user_arn, key_admins_arn_list, key_users_arn_list)
    
    # KMS Key Alias Creattion
    create_kms_key_alias(kms_client, kms_key_id, key_alias)

    return kms_key_id

def get_kms_key_by_alias(kms_client, key_alias):
    """
    Extract KMS Key using Key Alias
    """
    try:
        key = kms_client.describe_key(KeyId=key_alias)
    except:
        print(f"Could not describe a KMS key for alias `{key_alias}`.")
    else:
        return key

def get_current_timestamp_string() -> str:
    """
    Getting current timestamp
    """
    return str(datetime.now(timezone.utc))

def create_signature(kms_client, kms_key_id, data: dict) -> str:
    """
    Creates signature using KMS:Sign action and use it as signature part for the final JWT token
    """
    ## Prepare JWT header, JWT Payload and Signing Message for KMS      
    header = {"alg": JWT_ALGO, "typ": "JWT"}
    
    token_components = {
        "header":  base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("="),
        "payload": base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("="),
    }
    
    signing_message = json.dumps(data)
    
    ## Generating Signature
    print(f"Generating Signature with KMS Key ID: `{kms_key_id}` \n")
    signature: bytes = kms_client.sign(
        KeyId=kms_key_id,
        Message=signing_message.encode(), 
        SigningAlgorithm=KMS_SIGNING_ALGO,
        MessageType="RAW"
    )["Signature"]
    
    token_signature = base64.urlsafe_b64encode(signature).decode()
    token_components["signature"] = token_signature
    token = f'{token_components["header"]}.{token_components["payload"]}.{token_components["signature"]}'
    
    return token

def verify_signature(kms_client, kms_key_id, token):
    """
    Verify the signature attached with JWT token using KMS:Verify action
    """
    try:
        # Decode the JWT Token without verifying signature to demonstrate the data
        payload_msg = jwt.decode(jwt=token, algorithms=[JWT_ALGO], options=dict(verify_signature=False))
        payload_msg = json.dumps(payload_msg)
        print(f"Original Message that was signed: {payload_msg}\n")
        
        original_signature = base64.urlsafe_b64decode(bytes(token.split(".")[2], 'utf-8'))
        
        verifiction_response = kms_client.verify(KeyId=kms_key_id, 
                                Message=payload_msg.encode(),
                                Signature=original_signature,
                                SigningAlgorithm=KMS_SIGNING_ALGO)
        print(f"KMS Verification Response: {verifiction_response}\n")
        verified = verifiction_response["SignatureValid"]
        print(f"Is Signature varified? -> {verified}\n")
    except jwt.InvalidSignatureError:
        print("Invalid Signature")
    except jwt.DecodeError:
        print("Invalid Signature: Decoding Failed")

def main():

    # Get the KMS client
    kms_client = get_kms_client(KMS_KEY_REGION)

    # Get KMS Key
    key_alias = f"alias/{KMS_KEY_ALIAS}"
    kms_key = get_kms_key_by_alias(kms_client, key_alias)
    
    if kms_key:
        kms_key_id = kms_key["KeyMetadata"]["KeyId"]
        print(f"(Existing) KMS key to be used: `{kms_key_id}`")
    else:
        print(f"================= Creating KMS Key and aliasing it with `{key_alias}` =================\n")

        kms_key_id = configure_kms_key(kms_client, key_alias)

    # Prepare the message to be signed
    print("\n================= Preparing Message to be signed =================\n")
    timestamp = get_current_timestamp_string() 
    data = dict(name = "Ankit Jain",
                   email = "ankii.jain@gmail.com",
                   organization = "ARJStack",
                   action = "Signing Test",
                   signing_time = timestamp)

    signing_message = json.dumps(data)
    print(f"Message to be signed: {signing_message}")

    # Signing the message
    print(f"\n================= Creating Signature with KMS Key `{kms_key_id}` =================\n")
    token = create_signature(kms_client, kms_key_id, data)
    print(f"Signed JWT Token: {token}")
    
    # Verifying the message/signature
    print(f"\n================= Verifying Signature with `{kms_key_id}` =================\n")
    verify_signature(kms_client, kms_key_id, token)

if __name__ == "__main__":
    main()