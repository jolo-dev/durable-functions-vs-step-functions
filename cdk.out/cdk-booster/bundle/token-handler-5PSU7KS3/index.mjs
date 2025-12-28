"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// lambdas/shared/token-handler.ts
var token_handler_exports = {};
__export(token_handler_exports, {
  handler: () => handler
});
module.exports = __toCommonJS(token_handler_exports);
var import_client_dynamodb = require("@aws-sdk/client-dynamodb");
var import_client_lambda = require("@aws-sdk/client-lambda");
var import_client_sfn = require("@aws-sdk/client-sfn");
var sfn = new import_client_sfn.SFNClient({});
var ddb = new import_client_dynamodb.DynamoDBClient({});
var handler = async (event) => {
  console.log(event);
  const payload = typeof event.body === "string" ? JSON.parse(event.body) : event.body;
  const { email, token, code } = payload;
  if (!token || !code) {
    return { statusCode: 400, body: JSON.stringify({ error: "token and code required" }) };
  }
  const stored = await ddb.send(
    new import_client_dynamodb.GetItemCommand({
      TableName: process.env.TABLE_NAME,
      Key: { id: { S: email }, sort: { S: code } }
    })
  );
  console.log("taskToken GetItemCommand", stored);
  const expectedCode = stored.Item?.sort?.S;
  if (expectedCode !== code) {
    if (!event.body.durable) {
      await sfn.send(new import_client_sfn.SendTaskFailureCommand({
        taskToken: token,
        cause: "Invalid verification code"
      }));
    }
    return { statusCode: 400, body: JSON.stringify({ error: "Invalid verification code" }) };
  }
  if (payload.durable) {
    console.log("Is a durable handler invocation");
    const client = new import_client_lambda.LambdaClient();
    const command = new import_client_lambda.SendDurableExecutionCallbackSuccessCommand({
      CallbackId: token
    });
    await client.send(command);
  } else {
    const cmd = new import_client_sfn.SendTaskSuccessCommand({
      taskToken: token,
      output: JSON.stringify({ verification: "ok" })
      // any payload you want the state machine to receive
    });
    const result = await sfn.send(cmd);
    console.log("taskToken result", result);
  }
  await ddb.send(
    new import_client_dynamodb.DeleteItemCommand({
      TableName: process.env.TABLE_NAME,
      Key: { id: { S: email } }
    })
  );
  return { statusCode: 200, body: JSON.stringify({ message: "Verification accepted" }) };
};
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  handler
});
