"""
 * Here is an example of a gggpay sdk
"""

from gggpay.gggpayCfg import gggpayCfg
from gggpay.gggpaySdk import gggpaySdk

# docs : https://doc.gggpay.org/docs/quickstart/setup
# payment-method: https://doc.gggpay.org/docs/appendix/payment-method
# dictionary : https://doc.gggpay.org/docs/appendix/dictionary

# initialize this configuration
# verNo GGGPay Api Version Number, default: v1
# apiUrl GGGPay Api Url
# appId in developer settings : App Id
# key in developer settings : Key
# secret in developer settings : secret
# serverPubKey in developer settings : Server Public Key
# privateKey in developer settings : Private Key
# gggpayCfg.init(verNo, apiUrl, appId, key, secret, serverPubKey, privateKey)

# Here is an example of a deposit
# return deposit result: code=1,message=,transactionId=12817291,paymentUrl=https://www.xxxx...
depositResult = gggpaySdk.deposit("10001", 1.06, "MYR", "TNG_MY", "GGGPay Test",
                                  "gggpay@hotmail.com", "0123456789")
print(depositResult)

# Here is an example of a withdraw
# return withdraw result: code=1,message=,transactionId=12817291
withdrawResult = gggpaySdk.withdraw("10012", 1.06, "MYR", "CIMB",
                                    "GGGPay Test", "234719327401231", "", "gggpay@hotmail.com", "0123456789")
print(withdrawResult)

# Here is an example of a detail
# return detail result: code,message,transactionId,amount,fee
detailResult = gggpaySdk.detail("10921", 1)
print(detailResult)

# Decrypt the encrypted information in the callback
jsonstr = gggpaySdk.symDecrypt("encryptedData .........")
print(jsonstr)
