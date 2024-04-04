import strutils, strscans, strformat, json, times, os
import presto/[route, server]
import stew/byteutils
import db_connector/db_mysql
import dotenv
import jwt

proc validate(pattern: string, value: string): int = 0

var router = RestRouter.init(validate)

# 输入 {"address": ""}
# 输出 {
# "code": 200,
# "message": "success",
# "result": {
#     "expireAt": expirationTime,
#     "issuedAt": issueAt,
#     "nonce": nonce,
#     "signData": signData
# }
# }
router.api(MethodPost, "/api/signData") do (contentBody: Option[ContentBody]) -> RestApiResponse:
    var body: JsonNode
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

# 输入 
# {"nonce":1712201105278,
#  "signData":"app.xsniper.ai wants you to sign in with your Ethereum account:\n0xE5e44aD5214005Aa9Bd9C720a0B3FF233E48E9CB\n\n\nURI: https://app.xsniper.ai\nVersion: 1\nChain ID: 1\nNonce: 1712201105278\nIssued At: 2024-04-04T03:25:05Z\nExpiration Time: 2024-04-04T03:45:05Z\nRequest ID: 1712201105278\nResources:\n- https://resource1.com",
#  "signatrue":"0x5eac29b5bee5e9bdb052d55ea71ac9a1e2ea868e723226c950aa142b485198c77d86146f48b39ead6a84e52cf4c648bdeecd9af842951086b945f028e689bc571c"}
# 输出
# {
#   "code": 200,
#   "message": "success",
#   "result": {
#     "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTYwMDAyMywiaXNzIjoidnNmcmFtZSJ9.gXGlspOE2mOMbWLfBqu-Nin43rZ1KcXpkqME4hhUYvI",
#   }
# }
router.api(MethodPost, "/api/signIn") do (contentBody: Option[ContentBody]) -> RestApiResponse:
    var body: JsonNode
    try:
        body = contentBody.get().data.bytesToString.parseJson
        echo body
        var signData = body["signData"].getStr
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

            RestApiResponse.response($response, Http200, "application/json")
        else:
            RestApiResponse.response("invalid singature", Http200, "text/plain")
    except Exception as e:
        echo e.name
        RestApiResponse.response(e.msg, Http500, "text/plain")

router.api(MethodPost, "/api/upload") do (contentBody: Option[ContentBody]) -> RestApiResponse:
    var body: JsonNode
    try:
        body = contentBody.get().data.bytesToString.parseJson
        echo body
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
            RestApiResponse.response($response, Http200, "application/json")
        else:
            RestApiResponse.response("invalid token", Http200, "text/plain")
    except Exception as e:
        RestApiResponse.response(e.msg, Http500, "text/plain")

# eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTYwMDAyMywiaXNzIjoidnNmcmFtZSJ9.gXGlspOE2mOMbWLfBqu-Nin43rZ1KcXpkqME4hhUYvI
router.api(MethodPost, "/api/records") do (contentBody: Option[ContentBody]) -> RestApiResponse:
    var body: JsonNode
    try:
        body = contentBody.get().data.bytesToString.parseJson
        echo body
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
        RestApiResponse.response($response, Http200, "application/json")
    except Exception as e:
        RestApiResponse.response(e.msg, Http500, "text/plain")

let restServer = RestServerRef.new(router, initTAddress("127.0.0.1:9000")).get
restServer.start()

runForever()

