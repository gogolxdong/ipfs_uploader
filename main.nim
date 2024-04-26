import strutils, strscans, strformat, json, times, os
import presto/[route, server]
import stew/byteutils
import db_connector/db_mysql
import dotenv
import jwt
import secp256k1, eth/keys, eth/common/eth_hash, sequtils, stew/byteutils

proc addressToPublicKey(address: string): PublicKey =
  return PublicKey.fromHex(address).get

proc validate(pattern: string, value: string): int = 0

var router = RestRouter.init(validate)


router.api(MethodPost, "/omnimuse/eth_signData") do (contentBody: Option[ContentBody]) -> RestApiResponse:
  {.gcsafe.}:
    var body: JsonNode
    var headers = HttpTable.init([("Access-Control-Allow-Origin", "*")])
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
        RestApiResponse.response($response, Http200, "application/json",headers=headers)
    except Exception as e:
        var response = %*{
            "code": 500,
            "message": e.msg
        }
        RestApiResponse.response($response, Http500, "application/json",headers=headers)


router.api(MethodPost, "/omnimuse/eth_signIn") do (contentBody: Option[ContentBody]) -> RestApiResponse:
  {.gcsafe.}:
    var body: JsonNode
    var headers = HttpTable.init([("Access-Control-Allow-Origin", "*")])
    try:
        body = contentBody.get().data.bytesToString.parseJson
        # echo body
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

        # echo "signature:", signature
        # var sig = Signature.fromHex(signature).get
        # var msgHash = keccakHash(signData)
        # var publicKey = keys.recover(sig, signData.toOpenArrayByte(signData.low, signData.high)).get
        # echo "publicKey:", publicKey
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
            load()
            var dbUser = getEnv("DBUSER")
            var dbPassword = getEnv("DBPASSWORD")
            var dbName = getEnv("DBNAME")
            var db = open("127.0.0.1:3306", dbUser,dbPassword,dbName)
            defer: db.close()
            if not db.setEncoding("utf8"):
                return
            db.exec(sql"INSERT INTO user (address, token, create_time) VALUES (?,?,?) ON DUPLICATE KEY UPDATE token=?", address, token, now().toTime.toUnix, token)
            RestApiResponse.response($response, Http200, "application/json", headers=headers)
        else:
            var response = %* {
                "code": 200,
                "message": "invalid singature",
            }
            RestApiResponse.response($response, Http200, "application/json", headers=headers)
    except Exception as e:
        var response = %* {
                "code": 500,
                "message": e.msg,
            }
        RestApiResponse.response(e.msg, Http500, "application/json",headers=headers)

router.api(MethodPost, "/omnimuse/upload") do (contentBody: Option[ContentBody]) -> RestApiResponse:
  {.gcsafe.}:   
    var headers = HttpTable.init([("Access-Control-Allow-Origin", "*")])
    var body: JsonNode
    var response = %* {
        "code": 200,
        "message": "success",
    }
    try:
        body = contentBody.get().data.bytesToString.parseJson
        echo "upload:", body

        if request.headers.contains("Authorization"):
            var token = request.headers.getString("Authorization")[7..^1]
            let jwtToken = token.toJWT()
            var secret = "secret"
            if jwtToken.verify(secret, HS256):
                var cid = body["path"].getStr
                var fileName = body["file_name"].getStr
                load()
                var dbUser = getEnv("DBUSER")
                var dbPassword = getEnv("DBPASSWORD")
                var dbName = getEnv("DBNAME")
                var db = open("127.0.0.1:3306", dbUser,dbPassword,dbName)
                defer: db.close()
                if not db.setEncoding("utf8"):
                    return
                var address = db.getValue(sql"select address from user where token=?", token)
                if address != "":
                    db.exec(sql"INSERT INTO record (address, cid, create_time, file_name) values (?,?,?,?) ON DUPLICATE KEY UPDATE update_time=?", address, cid, now().toTime.toUnix, fileName, now().toTime.toUnix)
                    RestApiResponse.response($response, Http200, "application/json",headers=headers)
                else:
                    response["message"] = %"invalid address"
                    RestApiResponse.response($response, Http200, "application/json",headers=headers)
            else:
                response["message"] = %"invalid token"
                RestApiResponse.response($response, Http200, "application/json",headers=headers)
        else:
            response["message"] = %"invalid token"
            RestApiResponse.response($response, Http200, "application/json",headers=headers)
    except Exception as e:
        var strace: string = e.msg & "\n"
        for t in e.trace:
            strace.add &"{t.filename} {t.line} {t.procname} {t.frameMsg}\n"
        response["message"] = %strace
        
        RestApiResponse.response($response, Http500, "application/json",headers=headers)

router.api(MethodPost, "/omnimuse/records") do (contentBody: Option[ContentBody]) -> RestApiResponse:
  {.gcsafe.}:
    var headers = HttpTable.init([("Access-Control-Allow-Origin", "*")])
    var body = newJObject()
    try:
        if contentBody.isSome:
            body = contentBody.get().data.bytesToString.parseJson
        if request.headers.contains("Authorization"):
            var page = if body.hasKey"page": body["page"].getInt else:0
            var pageSize = if body.hasKey"pageSize": body["pageSize"].getInt else:0
            var token = request.headers.getString("Authorization")[7..^1]
            load()
            var dbUser = getEnv("DBUSER")
            var dbPassword = getEnv("DBPASSWORD")
            var dbName = getEnv("DBNAME")
            var db = open("127.0.0.1:3306", dbUser,dbPassword,dbName)
            defer: db.close()
            if not db.setEncoding("utf8"):
                return
            var response = %* {
                "code": 200,
                "message": "success",
                "result": []
            }
            if page < 1:
                response["message"] = %"invalid page"
                result = RestApiResponse.response($response, Http200, "application/json",headers=headers)
                return
            var address = db.getValue(sql"select address from user where token=?", token)
            var limit = if pageSize != 0 : &" limit {(page-1)*pageSize}, {page*pageSize}" else: ""
            var count = db.getValue(sql"select count(*) from record where address=? ORDER BY create_time DESC", address)
            var selectRecordDesc = "select address,cid,create_time, file_name from record where address=? ORDER BY create_time DESC"
            var statement = selectRecordDesc & limit
            echo "statement:", statement
            var rows = db.getAllRows(sql statement, address) 
     
            response["total"] = %count
            for row in rows:
                response["result"].add %*{"address": row[0], "cid":  row[1], "create_time": row[2], "file_name": row[3]}
            RestApiResponse.response($response, Http200, "application/json",headers=headers)
        else:
            var response = %* {
                "code": 200,
                "message": "invalid Authorization"
            }
            RestApiResponse.response($response, Http200, "application/json",headers=headers)
    except Exception as e:
        var response = %* {
                "code": 200,
                "message": "invalid Authorization"
            }
        var strace: string = e.msg & "\n"
        for t in e.trace:
            strace.add &"{t.filename} {t.line} {t.procname} {t.frameMsg}\n"
        response["message"] = %strace
        RestApiResponse.response($response, Http500, "application/json",headers=headers)

router.api(MethodGet, "/count") do (contentBody: Option[ContentBody]) -> RestApiResponse:
  {.gcsafe.}:
    var headers = HttpTable.init([("Access-Control-Allow-Origin", "*")])
    try:
        load()
        var dbUser = getEnv("DBUSER")
        var dbPassword = getEnv("DBPASSWORD")
        var dbName = getEnv("DBNAME")
        var db = open("127.0.0.1:3306", dbUser,dbPassword,dbName)
        defer: db.close()
        if not db.setEncoding("utf8"):
            return

        var count = db.getValue(sql"select count(*) from record")
        RestApiResponse.response($count, Http200, "text/plain",headers=headers)
    except Exception as e:
        var response = %* {
                "code": 200,
                "message": "invalid Authorization"
            }
        var strace: string = e.msg & "\n"
        for t in e.trace:
            strace.add &"{t.filename} {t.line} {t.procname} {t.frameMsg}\n"
        response["message"] = %strace
        RestApiResponse.response($response, Http500, "application/json",headers=headers)

let restServer = RestServerRef.new(router, initTAddress("127.0.0.1:9000")).get
restServer.start()

runForever()

