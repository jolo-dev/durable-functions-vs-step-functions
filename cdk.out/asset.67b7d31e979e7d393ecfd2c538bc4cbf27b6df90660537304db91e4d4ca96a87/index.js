"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
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
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// asset-input/lambdas/shared/signal-handler.ts
var signal_handler_exports = {};
__export(signal_handler_exports, {
  handler: () => handler
});
module.exports = __toCommonJS(signal_handler_exports);
var import_client_dynamodb = require("@aws-sdk/client-dynamodb");
var dynamoClient = new import_client_dynamodb.DynamoDBClient({});
var handler = async (event) => {
  console.log("Signal handler triggered:", JSON.stringify(event, null, 2));
  try {
    const body = typeof event.body === "string" ? JSON.parse(event.body) : event.body;
    const { requestId, value, taskToken } = body;
    if (!requestId) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: "Missing requestId" })
      };
    }
    if (taskToken) {
      await dynamoClient.send(new import_client_dynamodb.UpdateItemCommand({
        TableName: process.env.TABLE_NAME,
        Key: {
          id: { S: requestId }
        },
        UpdateExpression: "SET #signal = :signal, taskToken = :token",
        ExpressionAttributeNames: {
          "#signal": "signal"
        },
        ExpressionAttributeValues: {
          ":signal": { S: JSON.stringify(value) }
        }
      }));
      if (value !== void 0) {
        const { SFNClient } = await import("@aws-sdk/client-sfn");
        const sfnClient = new SFNClient({});
        await sfnClient.send({
          taskToken,
          output: JSON.stringify(value)
        });
      }
      return {
        statusCode: 200,
        body: JSON.stringify({
          message: "Signal sent to Step Functions",
          requestId,
          value
        })
      };
    }
    await dynamoClient.send(new import_client_dynamodb.PutItemCommand({
      TableName: process.env.TABLE_NAME,
      Item: {
        id: { S: `signal-${requestId}` },
        requestId: { S: requestId },
        value: { S: JSON.stringify(value) },
        timestamp: { S: (/* @__PURE__ */ new Date()).toISOString() }
      }
    }));
    return {
      statusCode: 200,
      body: JSON.stringify({
        message: "Signal stored for Durable Functions",
        requestId,
        value
      })
    };
  } catch (error) {
    console.error("Error in signal handler:", error);
    return {
      statusCode: 500,
      body: JSON.stringify({
        error: "Failed to process signal",
        details: error instanceof Error ? error.message : "Unknown error"
      })
    };
  }
};
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  handler
});
