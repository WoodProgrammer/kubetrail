import boto3
from cloudtrail import CloudTrail
from optparse import OptionParser
from k8s import Kubernetes

def generateSaPrefix(sa, namespace):
    return "system:serviceaccount:{}:{}".format(namespace, sa)

if __name__ == "__main__":
    print("\U0001F525 \U0001F525 \U0001F525 \U0001F525 \U0001F525 \U0001F525 \U0001F525 \U0001F525")
    print("""
_   __     _       _______        _   _ 
| |/ /    | |     |__   __|      (_) | |
| ' /_   _| |__   ___| |_ __ __ _ _  | |
|  <| | | | '_ \ / _ \ | '__/ _` | | | |
| . \ |_| | |_) |  __/ | | | (_| | | | |
|_|\_\__,_|_.__/ \___|_|_|  \__,_|_| |_|

CloudTrail Analyzer for EKS IRSA Resources version number 0.0.1

    """)
    k8sObj = Kubernetes()
    parser = OptionParser()
    
    obj = CloudTrail()

    parser.add_option("-s", "--service-account", dest="serviceaccount",
                    help="The name of the serviceaccount")
    
    parser.add_option("-n", "--namespace", dest="namespace",
                    help="The name of the namespace")

    (options, args) = parser.parse_args()

    saName = options.serviceaccount
    namespace = options.namespace

    userName = generateSaPrefix(saName, namespace)
    
    roleName = k8sObj.parseSA(saName)
    #print(roleName)

    rolePermissionList = obj.getPermissionList(roleName)

    #print(rolePermissionList)
    print("|Permission Name| Usage Count|")
    for permission in rolePermissionList:
        client = boto3.client("cloudtrail")
        results = obj.queryEvents(client, userName, permission)
        print("|{}| {}|".format(permission, results[permission]), end='   ')
