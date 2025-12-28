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

// asset-input/lambdas/durable/index.ts
var durable_exports = {};
__export(durable_exports, {
  handler: () => handler
});
module.exports = __toCommonJS(durable_exports);

// asset-input/lambdas/shared/send-email.ts
var import_client_ses = require("@aws-sdk/client-ses");
var import_client_dynamodb = require("@aws-sdk/client-dynamodb");
var sesClient = new import_client_ses.SESClient({});
var dynamoClient = new import_client_dynamodb.DynamoDBClient({});
var sendEmail = async (request) => {
  const { to, subject, body: emailBody, requestId } = request;
  if (!to || !subject || !emailBody) {
    throw new Error("Missing required fields: to, subject, body");
  }
  const timestamp = (/* @__PURE__ */ new Date()).toISOString();
  const itemId = requestId || `email-${Date.now()}`;
  await dynamoClient.send(new import_client_dynamodb.PutItemCommand({
    TableName: process.env.TABLE_NAME,
    Item: {
      id: { S: itemId },
      to: { S: to },
      subject: { S: subject },
      body: { S: emailBody },
      status: { S: "sent" },
      timestamp: { S: timestamp }
    }
  }));
  const sendEmailCommand = new import_client_ses.SendEmailCommand({
    Source: process.env.SENDER_EMAIL,
    Destination: {
      ToAddresses: [to]
    },
    Message: {
      Subject: { Data: subject },
      Body: {
        Text: { Data: emailBody },
        Html: { Data: emailBody.replace(/\n/g, "<br>") }
      }
    }
  });
  const emailResult = await sesClient.send(sendEmailCommand);
  return {
    requestId: itemId,
    messageId: emailResult.MessageId,
    timestamp,
    status: "sent"
  };
};

// asset-input/lambdas/shared/check-value.ts
var import_client_dynamodb2 = require("@aws-sdk/client-dynamodb");
var dynamoClient2 = new import_client_dynamodb2.DynamoDBClient({});
var checkValue = async (requestId) => {
  const getItemResult = await dynamoClient2.send(new import_client_dynamodb2.GetItemCommand({
    TableName: process.env.TABLE_NAME,
    Key: {
      id: { S: requestId }
    }
  }));
  if (!getItemResult.Item) {
    throw new Error(`Request ${requestId} not found`);
  }
  const item = getItemResult.Item;
  const status = item.status?.S || "unknown";
  const timestamp = item.timestamp?.S || "";
  const isCorrect = status === "sent";
  await dynamoClient2.send(new import_client_dynamodb2.UpdateItemCommand({
    TableName: process.env.TABLE_NAME,
    Key: {
      id: { S: requestId }
    },
    UpdateExpression: "SET #status = :status, checked = :checked, checkResult = :result",
    ExpressionAttributeNames: {
      "#status": "status"
    },
    ExpressionAttributeValues: {
      ":status": { S: isCorrect ? "success" : "incorrect" },
      ":checked": { S: (/* @__PURE__ */ new Date()).toISOString() },
      ":result": { S: isCorrect.toString() }
    }
  }));
  return {
    requestId,
    status,
    timestamp,
    isCorrect,
    checkResult: isCorrect ? "success" : "incorrect",
    checkedAt: (/* @__PURE__ */ new Date()).toISOString()
  };
};

// asset-input/lambdas/shared/signal-utils.ts
var import_client_dynamodb3 = require("@aws-sdk/client-dynamodb");
var dynamoClient3 = new import_client_dynamodb3.DynamoDBClient({});
var MAX_WAIT_TIME = 300;
var waitForSignal = async (requestId, taskToken) => {
  const startTime = Date.now();
  while (Date.now() - startTime < MAX_WAIT_TIME * 1e3) {
    const result = await dynamoClient3.send(new import_client_dynamodb3.GetItemCommand({
      TableName: process.env.TABLE_NAME,
      Key: {
        id: { S: requestId }
      }
    }));
    if (result.Item && result.Item.signal?.S) {
      return {
        received: true,
        value: JSON.parse(result.Item.signal.S)
      };
    }
    await new Promise((resolve) => setTimeout(resolve, 2e3));
  }
  return { received: false };
};

// asset-input/lambdas/durable/index.ts
var MockDurableContext = class {
  steps = /* @__PURE__ */ new Map();
  stepCounter = 0;
  async step(stepName, fn) {
    this.stepCounter++;
    console.log(`Executing step ${this.stepCounter}: ${stepName}`);
    const result = await fn();
    this.steps.set(stepName, result);
    return result;
  }
  async wait_for_signal(stepName, options) {
    console.log(`Waiting for signal: ${stepName}, timeout: ${options.timeout.seconds}s`);
    return await waitForSignal(this.steps.get("sendEmail")?.requestId || "");
  }
  async send_task_success(taskToken, output) {
    console.log(`Task success for token: ${taskToken}`, output);
  }
};
var handler = async (event) => {
  console.log("Durable orchestrator triggered:", JSON.stringify(event, null, 2));
  const context = new MockDurableContext();
  const emailResult = await context.step("sendEmail", async () => {
    return await sendEmail(event);
  });
  const signalResult = await context.wait_for_signal("waitForSignal", {
    timeout: { seconds: 300 }
    // 5 minutes
  });
  const validationResult = await context.step("checkValue", async () => {
    return await checkValue(emailResult.requestId);
  });
  return {
    requestId: event.requestId || emailResult.requestId,
    emailResult,
    signalResult,
    validationResult,
    executionComplete: true
  };
};
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  handler
});
