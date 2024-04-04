import strutils, strscans, strformat, json, times, os
import presto/[route, server]
import stew/byteutils
import db_connector/db_mysql
import dotenv
import jwt
import secp256k1, eth/keys, eth/common/eth_hash, sequtils, stew/byteutils

proc sign_message(msg: openArray[char]): Signature =
  var secretKey: PrivateKey = PrivateKey.fromHex("d8e0554cf88475d3949960ccc63fe34f667df6bc42f736cb2fa5413eb0aaa58b").get
  var msgHash = keccakHash(msg)
  return sign(secretKey, @(msgHash.data))

proc verify_signature(msg: string, signature: Signature, pubKey: PublicKey): bool =
  var msgHash = keccakHash(msg)
  var publicKey = keys.recover(signature, msg.mapIt(it.byte)).get

proc addressToPublicKey(address: string): PublicKey =
  return PublicKey.fromHex(address).get

proc validate(pattern: string, value: string): int = 0

var router = RestRouter.init(validate)


router.api(MethodPost, "/omnimuse/eth_signData") do (contentBody: Option[ContentBody]) -> RestApiResponse:
  {.gcsafe.}:
    var body: JsonNode
    # var headers = HttpTable.init([("Access-Control-Allow-Origin", "*")])
    try:
        body = contentBody.get().data.bytesToString.parseJson
        let messageBody = "file.omnimuse.ai wants you to sign in with your Ethereum account:\n0xE5e44aD5214005Aa9Bd9C720a0B3FF233E48E9CB\n\n\nURI: https://app.xsniper.ai\nVersion: 1\nChain ID: 1\nNonce: 1712190095329\nIssued At: 2024-04-04T00:21:35Z\nExpiration Time: 2024-04-04T00:41:35Z\nRequest ID: 1712190095329\nResources:\n- https://resource1.com"

        var domain: string = "file.omnimuse.ai"
        var account: string = body["address"].getStr
        var uri: string = "https://file.omnimuse.ai"
        var version: string = "1"
        var chainId: string = "1"
        var nonce: int64 = now().toTime.toUnix
        var issueAt: string = now().format("yyyy-MM-dd'T'HH:mm:ss")
        var expirationTime: string = (now().toTime() + 20.minutes).format("yyyy-MM-dd'T'HH:mm:ss")
        var requestId: int = now().toTime.toUnix
        var signData = &"{domain} wants you to sign in with your Ethereum account:\n{account}\n\n\nURI: {uri}\nVersion: {version}\nChain ID: {chainId}\nNonce: {nonce}\nIssued At: {issueAt}\nExpiration Time: {expirationTime}\nRequest ID: {requestId}"
        var response = %*{
            "code": 200,
            "message": "success",
            "result": {
                "expireAt": expirationTime,
                "issuedAt": issueAt,
                "nonce": nonce,
                "signData": signData
            }
            }
        RestApiResponse.response(signData, Http200, "application/json")
    except Exception as e:
        echo e.name
        RestApiResponse.response(e.msg, Http500, "text/plain")


router.api(MethodPost, "/omnimuse/eth_signIn") do (contentBody: Option[ContentBody]) -> RestApiResponse:
  {.gcsafe.}:
    var body: JsonNode
    var headers = HttpTable.init([("Access-Control-Allow-Origin", "*")])
    try:
        body = contentBody.get().data.bytesToString.parseJson
        echo body
        var address = body["address"].getStr
        var signData = body["signData"].getStr
        var signature = body["signature"].getStr
        const pattern = "$+ wants you to sign in with your Ethereum account:\n$+\n\n\nURI: $+\nVersion: $+\nChain ID: $+\nNonce: $+\nIssued At: $+\nExpiration Time: $+\nRequest ID: $i"
        var domain: string
        var account: string
        var uri: string
        var version: string
        var chainId: string
        var nonce: string
        var issueAt: string
        var expirationTime: string
        var requestId: int
        var resources: string

        var sig = Signature.fromHex(signature).get

        var msgHash = keccakHash(signData)
        var publicKey = keys.recover(sig, signData.toOpenArrayByte(signData.low, signData.high)).get
        echo "publicKey:", publicKey
        var secret = "secret"
        if signData.scanf(pattern, domain, account, uri,version, chainId, nonce, issueAt, expirationTime,requestId, resources):
            var token = toJWT(%*{
                "header": {
                "alg": "HS256",
                "typ": "JWT"
                },
                "claims": {
                "userId": account,
                "exp": (getTime() + 1.days).toUnix()
                }
            })

            token.sign(secret)

            var response = %* {
                "code": 200,
                "message": "success",
                "result": {
                    "token": $token,
                }
                }
            echo &"{domain} {account} {uri} {version} {chainId} {nonce} {issueAt} {expirationTime} {requestId} {resources}"

            RestApiResponse.response($response, Http200, "application/json",headers=headers)
        else:
            RestApiResponse.response("invalid singature", Http200, "text/plain",headers=headers)
    except Exception as e:
        echo e.name
        RestApiResponse.response(e.msg, Http500, "text/plain",headers=headers)

router.api(MethodPost, "/omnimuse/upload") do (contentBody: Option[ContentBody]) -> RestApiResponse:
  {.gcsafe.}:   
    var headers = HttpTable.init([("Access-Control-Allow-Origin", "*")])
    var body: JsonNode
    try:
        body = contentBody.get().data.bytesToString.parseJson
        echo body
        if request.headers.contains("Authorization"):
            var token = request.headers.getString("Authorization")
            let jwtToken = token.toJWT()
            var secret = "secret"
            if jwtToken.verify(secret, HS256):
                var cid = body["cid"].getStr
                var response = %* {
                    "code": 200,
                    "message": "success",
                    }
                load()
                var dbUser = getEnv("DBUSER")
                var dbPassword = getEnv("DBPASSWORD")
                var dbName = getEnv("DBNAME")
                var db = open("127.0.0.1:3306", dbUser,dbPassword,dbName)
                defer: db.close()
                if not db.setEncoding("utf8"):
                    return
                var address = db.getValue(sql"select address from user where token=?", token)
                db.exec(sql"INSERT INTO record (address, cid) values (?,?)", address, cid)
                RestApiResponse.response($response, Http200, "application/json",headers=headers)
            else:
                RestApiResponse.response("invalid token", Http200, "text/plain",headers=headers)
        else:
             RestApiResponse.response("invalid token", Http200, "text/plain",headers=headers)
    except Exception as e:
        RestApiResponse.response(e.msg, Http500, "text/plain",headers=headers)

router.api(MethodPost, "/omnimuse/records") do (contentBody: Option[ContentBody]) -> RestApiResponse:
  {.gcsafe.}:
    var headers = HttpTable.init([("Access-Control-Allow-Origin", "*")])
    var body: JsonNode
    try:
        body = contentBody.get().data.bytesToString.parseJson
        if request.headers.contains("Authorization"):
            var token = request.headers.getString("Authorization")
            var response = %* {
                "code": 200,
                "message": "success",
                "result": []
                }
            load()
            var dbUser = getEnv("DBUSER")
            var dbPassword = getEnv("DBPASSWORD")
            var dbName = getEnv("DBNAME")
            var db = open("127.0.0.1:3306", dbUser,dbPassword,dbName)
            defer: db.close()
            if not db.setEncoding("utf8"):
                return
            var address = db.getValue(sql"select address from user where token=?", token)
            var rows = db.getAllRows(sql"select address,cid from record where address=?", address)
            for row in rows:
                response["result"].add %*{"address": row[0], "cid":  row[1]}
            RestApiResponse.response($response, Http200, "application/json",headers=headers)
        else:
            RestApiResponse.response("invalid token", Http200, "text/plain",headers=headers)
    except Exception as e:
        RestApiResponse.response(e.msg, Http500, "text/plain",headers=headers)

let restServer = RestServerRef.new(router, initTAddress("127.0.0.1:9000")).get
restServer.start()

runForever()

