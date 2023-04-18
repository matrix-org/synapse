from boto3 import client, resource
from botocore import exceptions

from boto3_type_annotations.s3 import Client, ServiceResource

BUCKET = "prod-closer-contact"

s3: Client = client("s3")
s3r: ServiceResource = resource("s3")
s3_paginator = s3.get_paginator("list_objects_v2")
s3_iterator = s3_paginator.paginate(
    Bucket=BUCKET,
    Prefix="prod-closer-contact",
    PaginationConfig={"MaxItems": 1000, "PageSize": 10},
)

filtered_iterator = s3_iterator.search(
    "Contents[?to_string(LastModified)<='\"2022-07-10 00:00:00+00:00\"']"
)

for (idx, key_data) in enumerate(filtered_iterator):
    try:
        rootObjectKey = key_data["Key"].replace("prod-closer-contact/", "")
        rootObject = s3r.Object(BUCKET, rootObjectKey).get()
        rootObjectSize = rootObject['ContentLength']
        nestedObjectSize = key_data["Size"]
        nth = idx + 1

        if rootObjectSize != nestedObjectSize:
            print(f"{nth} - {rootObjectKey} has a size of {rootObjectSize} but {key_data['Key']} has a size of {nestedObjectSize}")
        else:
            print(f"{nth} - {rootObjectKey} exists in root and nested folder, both have a size of {rootObjectSize}")
    except exceptions.ClientError as e:
        print(e)
