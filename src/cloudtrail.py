import boto3

class CloudTrail(object):
    def __init__(self):
        self.iam_client = boto3.client("iam")
        sts_client = boto3.client("sts")
        self.accountId = sts_client.get_caller_identity()["Account"]

    def queryEvents(self, client, userName, eventName):
        eventMap = {}
        eventMap[eventName] = 0
        paginator = client.get_paginator('lookup_events')
        page_iterator = paginator.paginate(
            LookupAttributes=[
                {
                    'AttributeKey': 'EventName',
                    'AttributeValue': "{}".format(eventName)
                }
            ]
        )
        for page in page_iterator:
            for event in page["Events"]:
                if event["Username"] == userName:
                    if eventName in self.eventMap.keys():
                        eventMap[eventName] += 1
                    else:
                        eventMap[eventName] = 0
                        
                else:
                    pass

        return eventMap

    def get_policy_permissions(self, policyName):
        permissionList = []


        if policyName.startswith("Amazon"):
            policyArn = "arn:aws:iam::aws:policy/{}".format(policyName)
        else:
            policyArn = "arn:aws:iam::{}:policy/{}".format(self.accountId, policyName)
        try:
            policy_version = self.iam_client.get_policy_version(
                PolicyArn = policyArn,
                VersionId='v2'
            )
            for data in policy_version["PolicyVersion"]["Document"]["Statement"]:
                for action in data["Action"]:
                    permissionList.append(action.split(":")[1])

        except Exception as exp:
            print(exp)

        return permissionList


    def getPermissionList(self, roleName):

        parsedRoleArn = roleName.split("role/")[1]

        permissionList = []

        response = self.iam_client.list_attached_role_policies(
            RoleName=parsedRoleArn
        )

        for policy in response["AttachedPolicies"]:
            
            permissionList = permissionList + self.get_policy_permissions(policy["PolicyName"])
        

        return permissionList
        

