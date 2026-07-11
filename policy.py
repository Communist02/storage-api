import json
import ssl
from fastapi import HTTPException
import httpcore
from httpx_aws_auth import AwsSigV4Auth, AwsCredentials
import httpx
import truststore
from config import config
from opensearch import OpenSearchManager


async def create_policy_to_user(username: str, collections: list) -> str:
    policy = {
        'Version': '2012-10-17',
        'Statement': []
    }
    default_policy = {
        'Effect': 'Allow',
        'Action': ['s3:CreateBucket'],
        'Resource': ['arn:aws:s3:::*']
    }
    policy['Statement'].append(default_policy)

    opensearch_policy = {
        "cluster_permissions": [],
        "index_permissions": [{
            "index_patterns": [
                config.opensearch_collections_index,
                config.opensearch_files_index
            ],
            "allowed_actions": [
                "read",
                "search",
                "get"
            ],
            "dls": {
                "bool": {
                    "should": []
                }
            }
        }]
    }

    for collection in collections:
        if collection['type'] != 'access_to_all':
            opensearch_policy['index_permissions'][0]['dls']['bool']['should'].append({
                'term': {
                    'collection_id': collection['id']
                }
            })
            bucket_policy: dict = {'Effect': 'Allow'}

            match collection['access_type_id']:
                case 1:
                    bucket_policy['Action'] = ['s3:*']
                case 2:
                    bucket_policy['Action'] = [
                        's3:GetBucketLocation',
                        's3:GetObject',
                        's3:ListBucket',
                        's3:PutObject',
                        's3:DeleteObject'
                    ]
                case 3:
                    bucket_policy['Action'] = [
                        's3:GetBucketLocation',
                        's3:GetObject',
                        's3:ListBucket'
                    ]
                case 4:
                    bucket_policy['Action'] = [
                        's3:GetBucketLocation',
                        's3:ListBucket',
                        's3:PutObject'
                    ]
            bucket_policy['Resource'] = [
                f'arn:aws:s3:::{collection['name']}/*']
            policy['Statement'].append(bucket_policy)

    # opensearch['index_permissions'][0]['dls'] = {
    #     "bool": {
    #         "should": [{"term": {"collection_id": cid}} for cid in dls]
    #     }
    # }

    auth = AwsSigV4Auth(
        credentials=AwsCredentials(config.access_key, config.secret_key),
        region='us-east-1',
        service='s3'
    )
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    async with httpx.AsyncClient(verify=False if config.debug_mode else ctx) as client:
        response = await client.put(
            f'https://{config.s3_url}/minio/admin/v3/add-canned-policy',
            params={'name': username},
            headers={'Content-Type': 'application/json'},
            auth=auth,
            json=policy,
            timeout=5
        )
    if response.status_code != 200:
        # print('Ошибка создания политики:', response.status_code)
        # print(response.text)
        raise HTTPException(
            status_code=response.status_code,
            detail=f'Ошибка создания политики: {response.text}'
        )

    opensearch_policy['index_permissions'][0]['dls'] = str(
        opensearch_policy['index_permissions'][0]['dls']).replace("'", '"')
    opensearch = OpenSearchManager()
    await opensearch.create_policy_to_user(username, opensearch_policy)
    return json.dumps(policy)


async def create_policy_to_all(collections: list) -> str:
    policy = {
        'Version': '2012-10-17',
        'Statement': []
    }
    default_policy = {
        'Effect': 'Allow',
        'Action': ['s3:CreateBucket'],
        'Resource': ['arn:aws:s3:::*']
    }
    policy['Statement'].append(default_policy)

    opensearch_policy = {
        "cluster_permissions": [],
        "index_permissions": [{
            "index_patterns": [
                config.opensearch_collections_index,
                config.opensearch_files_index
            ],
            "allowed_actions": [
                "read",
                "search",
                "get"
            ],
            "dls": {
                "bool": {
                    "should": []
                }
            }
        }]
    }

    for collection in collections:
        opensearch_policy['index_permissions'][0]['dls']['bool']['should'].append({
            'term': {
                'collection_id': collection['id']
            }
        })

        bucket_policy: dict = {'Effect': 'Allow'}
        bucket_policy['Action'] = [
            's3:GetBucketLocation',
            's3:GetObject',
            's3:ListBucket'
        ]
        bucket_policy['Resource'] = [f'arn:aws:s3:::{collection['name']}/*']
        policy['Statement'].append(bucket_policy)

    # date = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    auth = AwsSigV4Auth(
        credentials=AwsCredentials(config.access_key, config.secret_key),
        region='us-east-1',
        service='s3'
    )

    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        async with httpx.AsyncClient(verify=False if config.debug_mode else ctx) as client:
            response = await client.put(
                f'https://{config.s3_url}/minio/admin/v3/add-canned-policy',
                params={'name': 'all/system'},
                headers={'Content-Type': 'application/json'},
                auth=auth,
                json=policy,
                timeout=5,
            )
    except httpcore.ConnectError as error:
        print('Failed to connect to S3 storage')
        raise error
    if response.status_code != 200:
        print('S3 storage policy creation error:', response.status_code)
        print(response.text)

    opensearch_policy['index_permissions'][0]['dls'] = str(
        opensearch_policy['index_permissions'][0]['dls']
    ).replace("'", '"')
    opensearch = OpenSearchManager()
    try:
        response = await opensearch.create_policy_to_user('all/system', opensearch_policy)
    except ConnectionRefusedError as error:
        print('Failed to connect to OpenSearch')
        raise error

    return json.dumps(policy)
