import boto3
from cloudtrail import CloudTrail
from optparse import OptionParser

def generateSaPrefix(sa, namespace):
    return "system:serviceaccount:{}:{}".format(namespace, sa)

if __name__ == "__main__":
    parser = OptionParser()

    parser.add_option("-s", "--service-account", dest="serviceaccount",
                    help="The name of the serviceaccount")
    
    parser.add_option("-n", "--namespace", dest="namespace",
                    help="The name of the namespace")

    (options, args) = parser.parse_args()

    saName = options.serviceaccount
    namespace = options.namespace

    userName = generateSaPrefix(saName, namespace)

    client = boto3.client("cloudtrail")
    obj = CloudTrail(client)
    results = obj.queryEvents(userName, "ListBuckets")