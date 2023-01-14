import boto3

class CloudTrail(object):
    def __init__(self, client):
        self.client = client
        self.eventMap = {}

    def queryEvents(self, userName, eventName):
        paginator = self.client.get_paginator('lookup_events')
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
                        self.eventMap[eventName] += 1
                    else:
                        self.eventMap[eventName] = 0                
                        
                else:
                    pass

        return self.eventMap