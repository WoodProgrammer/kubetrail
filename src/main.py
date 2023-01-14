import boto3
from cloudtrail import CloudTrail
from optparse import OptionParser
from k8s import Kubernetes

def generateSaPrefix(sa, namespace):
    return "system:serviceaccount:{}:{}".format(namespace, sa)

if __name__ == "__main__":
    k8sObj = Kubernetes()

    parser = OptionParser()

    parser.add_option("-s", "--service-account", dest="serviceaccount",
                    help="The name of the serviceaccount")
    
    parser.add_option("-n", "--namespace", dest="namespace",
                    help="The name of the namespace")

    (options, args) = parser.parse_args()

    saName = options.serviceaccount
    namespace = options.namespace

    userName = generateSaPrefix(saName, namespace)
    
    getRolePermissions = k8sObj.parseSA(saName)


    for permission in getRolePermissions:

        client = boto3.client("cloudtrail")
        obj = CloudTrail(client)
        results = obj.queryEvents(userName, permission)