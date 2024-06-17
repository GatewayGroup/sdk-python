"""
 * Here is an example of a gateway sdk
"""

from gateway.gatewayCfg import gatewayCfg
from gateway.gatewaySdk import gatewaySdk

# initialize this configuration
# verNo gateway Api Version Number, default: v1
# apiUrl gateway Api Url
# appId in developer settings : App Id
# key in developer settings : Key
# secret in developer settings : secret
# serverPubKey in developer settings : Server Public Key
# privateKey in developer settings : Private Key
# gatewayCfg.init(verNo, apiUrl, appId, key, secret, serverPubKey, privateKey)

# Here is an example of a deposit
# return deposit result: code=1,message=,transactionId=12817291,paymentUrl=https://www.xxxx...
depositResult = gatewaySdk.deposit("10001", 1.06, "MYR", "TNG_MY", "gateway Test",
                                  "gateway@hotmail.com", "0123456789")
print(depositResult)

# Here is an example of a withdraw
# return withdraw result: code=1,message=,transactionId=12817291
withdrawResult = gatewaySdk.withdraw("10012", 1.06, "MYR", "CIMB",
                                    "gateway Test", "234719327401231", "", "gateway@hotmail.com", "0123456789")
print(withdrawResult)

# Here is an example of a detail
# return detail result: code,message,transactionId,amount,fee
detailResult = gatewaySdk.detail("10921", 1)
print(detailResult)

# Decrypt the encrypted information in the callback
jsonstr = gatewaySdk.symDecrypt("encryptedData .........")
print(jsonstr)
