// lambdas/shared/token-handler.ts
import { DynamoDBClient, GetItemCommand, DeleteItemCommand } from "@aws-sdk/client-dynamodb";
import { LambdaClient } from "@aws-sdk/client-lambda";
import { SFNClient, SendTaskFailureCommand, SendTaskSuccessCommand } from "@aws-sdk/client-sfn";
var sfn = new SFNClient({});
var ddb = new DynamoDBClient({});
var handler = async (event) => {
  console.log(event);
  const payload = typeof event.body === "string" ? JSON.parse(event.body) : event.body;
  const { email, token, code } = payload;
  if (!token || !code) {
    return { statusCode: 400, body: JSON.stringify({ error: "token and code required" }) };
  }
  const stored = await ddb.send(
    new GetItemCommand({
      TableName: process.env.TABLE_NAME,
      Key: { id: { S: email }, sort: { S: code } }
    })
  );
  console.log("taskToken GetItemCommand", stored);
  const expectedCode = stored.Item?.sort?.S;
  if (expectedCode !== code) {
    if (!event.body.durable) {
      await sfn.send(new SendTaskFailureCommand({
        taskToken: token,
        cause: "Invalid verification code"
      }));
    }
    return { statusCode: 400, body: JSON.stringify({ error: "Invalid verification code" }) };
  }
  if (payload.durable) {
    console.log("Is a durable handler invocation");
    const client = new LambdaClient();
    const command = new (await import("@aws-sdk/client-lambda")).SendDurableExecutionCallbackSuccessCommand({
      CallbackId: token,
      Result: JSON.stringify({
        verification: "ok"
      })
    });
    await client.send(
      command
    );
  } else {
    const cmd = new SendTaskSuccessCommand({
      taskToken: token,
      output: JSON.stringify({ verification: "ok" })
      // any payload you want the state machine to receive
    });
    const result = await sfn.send(cmd);
    console.log("taskToken result", result);
  }
  await ddb.send(
    new DeleteItemCommand({
      TableName: process.env.TABLE_NAME,
      Key: { id: { S: email } }
    })
  );
  return { statusCode: 200, body: JSON.stringify({ message: "Verification accepted" }) };
};
export {
  handler
};
