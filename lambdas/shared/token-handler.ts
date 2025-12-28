import { DynamoDBClient, GetItemCommand, DeleteItemCommand } from '@aws-sdk/client-dynamodb';
import { LambdaClient, SendDurableExecutionCallbackFailureCommand, SendDurableExecutionCallbackSuccessCommand } from '@aws-sdk/client-lambda';
import { SFNClient, SendTaskFailureCommand, SendTaskSuccessCommand } from '@aws-sdk/client-sfn';

const sfn = new SFNClient({});
const ddb = new DynamoDBClient({});
const lambda = new LambdaClient({});

interface Event {
  body: {
    token: string;
    code: string;
    email: string;
    durable?: boolean
  }
}

export const handler = async (event: Event) => {
  // -------------------------------------------------
  // 1️⃣ Parse incoming request
  // -------------------------------------------------
  console.log(event);
  const payload = typeof event.body === 'string' ? JSON.parse(event.body) : event.body;
  const { email, token, code } = payload;

  if (!token || !code) {
    return { statusCode: 400, body: JSON.stringify({ error: 'token and code required' }) };
  }

  // -------------------------------------------------
  // 2️⃣ (Optional) Verify the code against what you stored
  // -------------------------------------------------
  const stored = await ddb.send(
    new GetItemCommand({
      TableName: process.env.TABLE_NAME!,
      Key: { id: { S: email }, sort: { S: code } },
    })
  );

  console.log('taskToken GetItemCommand', stored)
  const expectedCode = stored.Item?.sort?.S;
  if (expectedCode !== code) {
    // you could also call SendTaskFailure here if you want the workflow to fail
    if (!event.body.durable) {
      await sfn.send(new SendTaskFailureCommand({
        taskToken: token,
        cause: 'Invalid verification code'
      }))
    } else {
      await lambda.send(new SendDurableExecutionCallbackFailureCommand({
        CallbackId: token,
        Error: {
          ErrorMessage: 'Invalid verification code'
        }
      }))
    }
    return { statusCode: 400, body: JSON.stringify({ error: 'Invalid verification code' }) };
  }

  // -------------------------------------------------
  // 3️⃣  Invoke Lambda directly with the callbackId
  // -------------------------------------------------
  if (payload.durable) {
    console.log('Is a durable handler invocation')
    const command = new SendDurableExecutionCallbackSuccessCommand({
      CallbackId: token,
      Result: JSON.stringify({
        verification: 'ok'
      })
    })
    await lambda.send(command);
  } else {
    // -------------------------------------------------
    // 3️⃣ Tell Step Functions the task succeeded
    // -------------------------------------------------
    const cmd = new SendTaskSuccessCommand({
      taskToken: token,
      output: JSON.stringify({ verification: 'ok' }), // any payload you want the state machine to receive
    });

    const result = await sfn.send(cmd);
    console.log('taskToken result', result)
  }
  // -------------------------------------------------
  // 4️⃣ Clean‑up (optional)
  // -------------------------------------------------
  await ddb.send(
    new DeleteItemCommand({
      TableName: process.env.TABLE_NAME!,
      Key: { id: { S: email }, sort: { S: token } },
    })
  );

  return { statusCode: 200, body: JSON.stringify({ message: 'Verification accepted' }) };
};

