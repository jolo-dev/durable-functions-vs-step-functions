import { InvokeCommand, LambdaClient } from "@aws-sdk/client-lambda";
import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { InvokerBody, LambdaResponse } from "../shared/types";

const lambdaClient = new LambdaClient()

export const handler: APIGatewayProxyHandlerV2 = async (event): Promise<LambdaResponse> => {
  console.log('durable-invoker', event)
  const body: InvokerBody = typeof event.body === 'string' ? JSON.parse(event.body || "{}") : event.body || {};
  const functionsArn = process.env.FUNCTION_ARN ?? 'durable-handler';
  console.log('durable-invoker functionsArn', functionsArn)
  await lambdaClient.send(
    new InvokeCommand({
      FunctionName: `${functionsArn}:$LATEST`,
      InvocationType: "Event",
      Payload: JSON.stringify({
        email: body.email
      })
    })
  );

  return { statusCode: 202, body: "Accepted" };
};
