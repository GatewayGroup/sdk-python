# import basic
import time
import json
import base64
import binascii
import requests

# import Crypto
from Crypto import Random
from Crypto.Hash import MD5
from Crypto.Cipher import AES
from Crypto.Util import Padding
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKC
from Crypto.Signature import PKCS1_v1_5 as Signature_PKC

# import config
from gateway.gatewayCfg import gatewayCfg


class gatewaySdk:

    # **
    # * rsa algorithm
    # */
    ALGORITHM = "aes-256-cbc"

    # **
    # * aes algorithm
    # */
    HASH_ALGORITHM = "rsa-sha256"

    # **
    # * encrypt auth info
    # */
    EncryptAuthInfo = ""

    # init
    def __init__(self):
        pass

    # **
    # * user deposit
    # * @param {*} orderId orderId order number - maxlength(40)
    # * @param {*} amount amount order amount - maxlength(20)
    # * @param {*} currency currency Empty default: MYR - maxlength(16)
    # * @param {*} payMethod payMethod FPX, TNG_MY, ALIPAY_CN, GRABPAY_MY, BOOST_MY - maxlength(16)
    # * @param {*} customerName customerName customer name - maxlength(64)
    # * @param {*} customerEmail customerEmail customer email - maxlength(64)
    # * @param {*} customerPhone customerPhone customer phone - maxlength(20)
    # * @returns code,message,paymentUrl,transactionId
    # */
    @staticmethod
    def deposit(orderId, amount, currency, payMethod, customerName, customerEmail, customerPhone) -> dict:
        try:
            token = gatewaySdk.__getToken()
            if gatewaySdk.__isnull(token):
                return {"code": 0, "message": "token is null"}
            if gatewaySdk.__isnull(currency):
                currency = "MYR"
            requestUrl = "gateway/" + gatewayCfg.VERSION_NO + "/createPayment"
            cnst = gatewaySdk.__generateConstant(requestUrl)
            # If callbackUrl and redirectUrl are empty, take the values ​​of [curl] and [rurl] in the developer center.
            # Remember, the format of json and the order of json attributes must be the same as the SDK specifications.
            # The sorting rules of Json attribute data are arranged from [a-z]
            bodyJson = "{\"customer\":{\"email\":\"" + customerEmail + "\",\"name\":\"" + customerName + "\",\"phone\":\"" + customerPhone + "\"},\"method\":\"" + payMethod + \
                "\",\"order\":{\"additionalData\":\"\",\"amount\":\"" + str(amount) + "\",\"currencyType\":\"" + \
                currency + "\",\"id\":\"" + orderId + "\",\"title\":\"Payment\"}}"
            #bodyJson = "{\"callbackUrl\":\"https://www.google.com\",\"customer\":{\"email\":\"" + customerEmail + "\",\"name\":\"" + customerName + "\",\"phone\":\"" + customerPhone + "\"},\"method\":\"" + payMethod + \
            #    "\",\"order\":{\"additionalData\":\"\",\"amount\":\"" + str(amount) + "\",\"currencyType\":\"" + \
            #    currency + "\",\"id\":\"" + orderId + "\",\"title\":\"Payment\"},\"redirectUrl\":\"https://www.google.com\"}"
            base64ReqBody = gatewaySdk.__sortedAfterToBased64(bodyJson)
            signature = gatewaySdk.__createSignature(cnst, base64ReqBody)
            encryptData = gatewaySdk.__symEncrypt(base64ReqBody)
            json = {"data": encryptData}
            dict = gatewaySdk.__post(requestUrl, token, signature,
                                    json, cnst["nonceStr"], cnst["timestamp"])
            if gatewaySdk.__isnull(dict["code"]) == False and gatewaySdk.__isnull(dict["encryptedData"]) == False and dict["code"] != 1:
                return dict
            decryptedData = gatewaySdk.symDecrypt(dict["encryptedData"])
            result = gatewaySdk.__tryParseJson(decryptedData)
            return result
        except Exception as e:
            return {"code": 0, "message": e}

    # **
    # * user withdraw
    # * @param {*} orderId orderId order number - maxlength(40)
    # * @param {*} amount amount order amount - maxlength(20)
    # * @param {*} currency currency Empty default: MYR - maxlength(16)
    # * @param {*} bankCode bankCode MayBank=MBB,Public Bank=PBB,CIMB Bank=CIMB,Hong Leong Bank=HLB,RHB Bank=RHB,AmBank=AMMB,United Overseas Bank=UOB,Bank Rakyat=BRB,OCBC Bank=OCBC,HSBC Bank=HSBC  - maxlength(16)
    # * @param {*} cardholder cardholder cardholder - maxlength(64)
    # * @param {*} accountNumber accountNumber account number - maxlength(20)
    # * @param {*} refName refName recipient refName - maxlength(64)
    # * @param {*} recipientEmail recipientEmail recipient email - maxlength(64)
    # * @param {*} recipientPhone recipientPhone recipient phone - maxlength(20)
    # * @returns code,message,transactionId
    # */
    @staticmethod
    def withdraw(orderId, amount, currency, bankCode, cardholder, accountNumber, refName, recipientEmail, recipientPhone) -> dict:
        try:
            token = gatewaySdk.__getToken()
            if gatewaySdk.__isnull(token):
                return {"code": 0, "message": "token is null"}
            if gatewaySdk.__isnull(currency):
                currency = "MYR"
            requestUrl = "gateway/" + gatewayCfg.VERSION_NO + "/withdrawRequest"
            cnst = gatewaySdk.__generateConstant(requestUrl)
            # payoutspeed contain "fast", "normal", "slow" ,default is : "fast"
            # Remember, the format of json and the order of json attributes must be the same as the SDK specifications.
            # The sorting rules of Json attribute data are arranged from [a-z]
            bodyJson = "{\"order\":{\"amount\":\"" + str(amount) + "\",\"currencyType\":\"" + currency + "\",\"id\":\"" + orderId + "\"},\"recipient\":{\"email\":\"" + recipientEmail + \
                "\",\"methodRef\":\"" + refName + "\",\"methodType\":\"" + bankCode + "\",\"methodValue\":\"" + \
                accountNumber + "\",\"name\":\"" + cardholder + \
                "\",\"phone\":\"" + recipientPhone + "\"}}"
            #bodyJson = "{\"callbackUrl\":\"https://www.google.com\",\"order\":{\"amount\":\"" + str(amount) + "\",\"currencyType\":\"" + currency + "\",\"id\":\"" + orderId + "\"},\"payoutspeed\":\"normal\",\"recipient\":{\"email\":\"" + recipientEmail + \
            #    "\",\"methodRef\":\"" + refName + "\",\"methodType\":\"" + bankCode + "\",\"methodValue\":\"" + \
            #    accountNumber + "\",\"name\":\"" + cardholder + \
            #    "\",\"phone\":\"" + recipientPhone + "\"}}"
            base64ReqBody = gatewaySdk.__sortedAfterToBased64(bodyJson)
            signature = gatewaySdk.__createSignature(cnst, base64ReqBody)
            encryptData = gatewaySdk.__symEncrypt(base64ReqBody)
            json = {"data": encryptData}
            dict = gatewaySdk.__post(requestUrl, token, signature,
                                    json, cnst["nonceStr"], cnst["timestamp"])
            if gatewaySdk.__isnull(dict["code"]) == False and gatewaySdk.__isnull(dict["encryptedData"]) == False and dict["code"] != 1:
                return dict
            decryptedData = gatewaySdk.symDecrypt(dict["encryptedData"])
            result = gatewaySdk.__tryParseJson(decryptedData)
            return result
        except Exception as e:
            return {"code": 0, "message": e}

    # **
    # * User deposit and withdrawal details
    # * @param {*} orderId transaction id
    # * @param {*} type 1 deposit,2 withdrawal
    # */
    @staticmethod
    def detail(orderId, type) -> dict:
        try:
            token = gatewaySdk.__getToken()
            if gatewaySdk.__isnull(token):
                return {"code": 0, "message": "token is null"}
            requestUrl = "gateway/" + gatewayCfg.VERSION_NO + "/getTransactionStatusById"
            cnst = gatewaySdk.__generateConstant(requestUrl)
            # Remember, the format of json and the order of json attributes must be the same as the SDK specifications.
            # The sorting rules of Json attribute data are arranged from [a-z]
            # type : 1 deposit,2 withdrawal
            bodyJson = "{\"transactionId\":\"" + \
                orderId + "\",\"type\":" + str(type) + "}"
            base64ReqBody = gatewaySdk.__sortedAfterToBased64(bodyJson)
            signature = gatewaySdk.__createSignature(cnst, base64ReqBody)
            encryptData = gatewaySdk.__symEncrypt(base64ReqBody)
            json = {"data": encryptData}
            dict = gatewaySdk.__post(requestUrl, token, signature,
                                    json, cnst["nonceStr"], cnst["timestamp"])
            if gatewaySdk.__isnull(dict["code"]) == False and gatewaySdk.__isnull(dict["encryptedData"]) == False and dict["code"] != 1:
                return dict
            decryptedData = gatewaySdk.symDecrypt(dict["encryptedData"])
            result = gatewaySdk.__tryParseJson(decryptedData)
            return result
        except Exception as e:
            return {"code": 0, "message": e}

    # **
    # * get server token
    # * @returns token
    # */
    @staticmethod
    def __getToken() -> str:
        if gatewaySdk.__isnull(gatewaySdk.EncryptAuthInfo):
            authString = gatewaySdk.__stringToBase64(
                gatewayCfg.CLIENT_ID+":" + gatewayCfg.CLIENT_SECRET)
            gatewaySdk.EncryptAuthInfo = gatewaySdk.__publicEncrypt(authString)
        json = {"data": gatewaySdk.EncryptAuthInfo}
        dict = gatewaySdk.__post("gateway/" + gatewayCfg.VERSION_NO +
                                "/createToken", "", "", json, "", "")
        if gatewaySdk.__isnull(dict["code"]) == False and gatewaySdk.__isnull(dict["encryptedToken"]) == False and dict["code"] == 1:
            token = gatewaySdk.symDecrypt(dict["encryptedToken"])
            return token
        raise Exception("__getToken exception")

    # **
    # * A simple http request method
    # * @param {*} url
    # * @param {*} param
    # * @returns
    # */
    @classmethod
    def __post(cls, url, token, signature, json, nonceStr, timestamp):
        if gatewayCfg.BASE_URL.endswith("/"):
            url = gatewayCfg.BASE_URL + url
        else:
            url = gatewayCfg.BASE_URL + "/" + url
        headers = {"Content-type": "application/json"}
        if gatewaySdk.__isnull(token) == False and gatewaySdk.__isnull(signature) == False and gatewaySdk.__isnull(nonceStr) == False and gatewaySdk.__isnull(timestamp) == False:
            headers = {"Content-type": "application/json", "Authorization": token, "X-Nonce-Str": nonceStr,
                       "X-Signature": signature,
                       "X-Timestamp": str(timestamp)}
        # json.dumps(data)
        req = requests.post(url, json=json, headers=headers)
        if req.status_code == 200:
            return req.json()
        return {}

    # **
    # * create a signature
    # * @param {*} constantVars
    # * @param {*} base64ReqBody
    # * @returns signature info
    # */
    @classmethod
    def __createSignature(cls, cnst, base64ReqBody: str) -> str:
        dataString = "data="+base64ReqBody+"&method="+cnst["method"]+"&nonceStr="+cnst["nonceStr"] + \
            "&requestUrl="+cnst["requestUrl"]+"&signType=" + \
            cnst["signType"]+"&timestamp="+str(cnst["timestamp"])
        signature = gatewaySdk.__sign(dataString)
        return cnst["signType"]+" " + signature

    # **
    # * generate constant
    # * @param {*} request url
    # * @returns constant
    # */
    @classmethod
    def __generateConstant(cls, requestUrl) -> dict:
        constant = {
            "method": "post",
            "nonceStr": gatewaySdk.__randomNonceStr(),
            "requestUrl": requestUrl,
            "signType": "sha256",
            "timestamp": int(round(time.time()*1000)),
        }
        return constant

    # **
    # * random nonceStr
    # * @returns nonceStr
    # */
    @classmethod
    def __randomNonceStr(cls) -> str:
        bytesData = Random.get_random_bytes(8)
        hex = gatewaySdk.__bytesToHex(bytesData)
        return hex

    # **
    # * Encrypt data based on the server"s public key
    # * @param {*} data data to be encrypted
    # * @returns encrypted data
    # */
    @classmethod
    def __publicEncrypt(cls, data: str) -> str:
        bytesData = gatewaySdk.__stringToBytes(data)
        rsaKey = RSA.import_key(gatewayCfg.SERVER_PUB_KEY)
        encryptCipher = Cipher_PKC.new(rsaKey)
        encryptBuffer = encryptCipher.encrypt(bytesData)
        hex = gatewaySdk.__bytesToHex(encryptBuffer)
        return hex

    # **
    # * Decrypt data according to the interface private key
    # * @param {*} encryptData data to be decrypted
    # * @returns decrypted data
    # */
    @classmethod
    def __privateDecrypt(cls, encryptData: str) -> dict:
        encryptBuffer = gatewaySdk.__hexToBytes(encryptData)
        rsaKey = RSA.import_key(gatewayCfg.PRIVATE_KEY)
        decryptCipher = Cipher_PKC.new(rsaKey)
        decryptBuffer = decryptCipher.decrypt(encryptBuffer)
        msg = gatewaySdk.__bytesToString(decryptBuffer)
        return gatewaySdk.__tryParseJson(msg)

    # **
    # * Payment interface data encryption method
    # * @param {*} message data to be encrypted
    # * @returns The encrypted data is returned in hexadecimal
    # */
    @classmethod
    def __symEncrypt(cls, message: str) -> str:
        key = gatewaySdk.__stringToBytes(gatewayCfg.CLIENT_SYMMETRIC_KEY)
        iv = gatewaySdk.__generateIv(gatewayCfg.CLIENT_SYMMETRIC_KEY)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        messageBuffer = gatewaySdk.__stringToBytes(message)
        messageBuffer = Padding.pad(messageBuffer, 16, style="pkcs7")
        encryptBuffer = cipher.encrypt(messageBuffer)
        encrypted = gatewaySdk.__bytesToHex(encryptBuffer)
        return encrypted

    # **
    # * Payment interface data decryption method
    # * @param {*} encryptedMessage The data that needs to be encryptedMessage, the result encrypted by __symEncrypt can be decrypted
    # * @returns Return the data content of utf-8 after decryption
    # */
    @staticmethod
    def symDecrypt(encryptedMessage: str) -> str:
        key = gatewaySdk.__stringToBytes(gatewayCfg.CLIENT_SYMMETRIC_KEY)
        iv = gatewaySdk.__generateIv(gatewayCfg.CLIENT_SYMMETRIC_KEY)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encryptBuffer = gatewaySdk.__hexToBytes(encryptedMessage)
        decryptBuffer = cipher.decrypt(encryptBuffer)
        decryptedText = gatewaySdk.__bytesToString(decryptBuffer)
        # Encryption function, if the text is less than 16 digits, fill it with spaces to 16 digits,
        # If it is greater than 16 but not a multiple of 16, it will be a multiple of 16.
        # After decryption, remove the supplementary spaces and use strip() to remove them
        decryptedText = decryptedText.rstrip("\x01").\
            rstrip("\x02").rstrip("\x03").rstrip("\x04").rstrip("\x05").\
            rstrip("\x06").rstrip("\x07").rstrip("\x08").rstrip("\x09").\
            rstrip("\x0a").rstrip("\x0b").rstrip("\x0c").rstrip("\x0d").\
            rstrip("\x0e").rstrip("\x0f").rstrip("\x10")
        decryptedText = decryptedText.replace("\n", "")
        decryptedText = decryptedText.replace("\t", "")
        decryptedText = decryptedText.replace("\r", "")
        decryptedText = decryptedText.replace("\v", "")
        return decryptedText

    # **
    # * private key signature
    # * @param {*} data
    # * @returns signature
    # */
    @classmethod
    def __sign(cls, data: str) -> str:
        rsaKey = RSA.import_key(gatewayCfg.PRIVATE_KEY)
        bytesData = gatewaySdk.__stringToBytes(data)
        sha256Hash = SHA256.new(bytesData)
        signer = Signature_PKC.new(rsaKey)
        signatureBuffer = signer.sign(sha256Hash)
        base64Bytes = binascii.b2a_base64(signatureBuffer)
        base64Str = gatewaySdk.__bytesToString(base64Bytes)
        return base64Str.rstrip().rstrip("\n").rstrip("\t")

    # **
    # * Public key verification signature information
    # * @param {*} data
    # * @param {*} signature
    # * @returns result true or false
    # */
    @classmethod
    def __verify(cls, data, signature: str) -> bool:
        rsaKey = RSA.import_key(gatewayCfg.SERVER_PUB_KEY)
        sign_data = base64.b64decode(signature.encode("utf-8").strip())
        encryptBuffer = gatewaySdk.__stringToBytes(data)
        signer = Signature_PKC.new(rsaKey)
        isVerify = signer.verify(sign_data, encryptBuffer)
        return isVerify

    # **
    # * Return base64 after sorting argument list
    # * @param {*} param
    # * @returns param to json base64
    # */
    @classmethod
    def __sortedAfterToBased64(cls, jsonStr: str) -> str:
        jsonBytes = gatewaySdk.__stringToBytes(jsonStr)
        jsonBase64 = gatewaySdk.__bytesToBase64(jsonBytes)
        return jsonBase64

    # **
    # * Generate an IV based on the data encryption key
    # * @param {*} symmetricKey
    # * @returns iv
    # */
    @classmethod
    def __generateIv(cls, symmetricKey: str) -> bytes:
        bytesData = gatewaySdk.__stringToBytes(symmetricKey)
        md5Hash = MD5.new(bytesData)
        iv = md5Hash.digest()
        return iv

    # **
    # * UTF8 String to bytes
    # * @param {*} data
    # * @returns bytes
    # */
    @classmethod
    def __stringToBytes(cls, data: str) -> bytes:
        byteData = data.encode("utf-8").strip()
        return byteData

    # **
    # * UTF8 String to base64
    # * @param {*} data
    # * @returns base64
    # */
    @classmethod
    def __stringToBase64(cls, data: str) -> str:
        bytesData = gatewaySdk.__stringToBytes(data)
        bytesBase64 = base64.b64encode(bytesData)
        base64Str = bytesBase64.decode("utf-8")
        return base64Str

    # **
    # * String to bytes
    # * @param {*} bytes
    # * @returns bytes
    # */
    @classmethod
    def __bytesToString(cls, byteData: bytes) -> str:
        strData = byteData.decode("utf-8")
        return strData

    # **
    # * Bytes to hex
    # * @param {*} bytes
    # * @returns hex
    # */
    @classmethod
    def __bytesToHex(cls, byteData: bytes) -> str:
        hexStr = byteData.hex()
        return hexStr

    # **
    # * Hex to bytes
    # * @param {*} hex
    # * @returns bytes
    # */
    @classmethod
    def __hexToBytes(cls, hexStr: str) -> bytes:
        byteData = binascii.unhexlify(hexStr)
        return byteData

    # **
    # * Bytes to base64
    # * @param {*} bytes
    # * @returns base64
    # */
    @classmethod
    def __bytesToBase64(cls, bytesData: bytes) -> str:
        bytesStr = bytesData.decode("utf-8")
        return gatewaySdk.__stringToBase64(bytesStr)

    # **
    # * Base64 to bytes
    # * @param {*} base64
    # * @returns bytes
    # */
    @classmethod
    def __base64ToBytes(cls, base64Data: str) -> bytes:
        dataStr = base64.b64decode(base64Data)
        return gatewaySdk.__stringToBytes(dataStr)

    # **
    # * 尝试将数据转成JSON
    # * @param {*} data
    # * @returns
    # */
    @classmethod
    def __tryParseJson(cls, data: str) -> dict:
        if type(data):
            jsonData = json.loads(data)
            return jsonData

    # **
    # * value is null
    # * @param {*} val
    # * @returns
    # */
    @classmethod
    def __isnull(cls, val) -> bool:
        if isinstance(val, str):
            if len(val) == 0:
                return True
            if str.strip(val) == "":
                return True
            if str.isspace(val):
                return True
            return False
        elif val == None:
            return True
        return False
