import { InvokeCommand, LambdaClient } from "@aws-sdk/client-lambda";
import { APIGatewayProxyHandlerV2 } from "aws-lambda";

const lambdaClient = new LambdaClient()

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  console.log('durable-invoker', event)
  const body = JSON.parse(event.body || "{}");
  const functionsArn = process.env.FUNCTION_ARN ?? 'durable-handler';
  console.log('durable-invoker functionsArn', functionsArn)
  await lambdaClient.send(
    new InvokeCommand({
      FunctionName: `${functionsArn}:$LATEST`,
      InvocationType: "Event", // Async invocation
      Payload: JSON.stringify({
        email: body.email
      })
    })
  );

  return { statusCode: 202, body: "Accepted" };
};
