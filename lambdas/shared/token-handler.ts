import { LambdaClient, SendDurableExecutionCallbackFailureCommand, SendDurableExecutionCallbackSuccessCommand } from '@aws-sdk/client-lambda';
import { SFNClient, SendTaskFailureCommand, SendTaskSuccessCommand } from '@aws-sdk/client-sfn';
import { APIGatewayProxyHandlerV2 } from 'aws-lambda';
import { TokenRequestBody, LambdaResponse } from './types';
import { checkValue } from './check-value';
import { deleteTokenEntry } from './dynamodb';

const sfn = new SFNClient({});
const lambda = new LambdaClient({});

export const handler: APIGatewayProxyHandlerV2 = async (event): Promise<LambdaResponse> => {
  console.log(event);
  const payload: TokenRequestBody = typeof event.body === 'string' ? JSON.parse(event.body || '{}') : event.body || {};
  const { email, token, code, durable } = payload;

  if (!token || !code || !email) {
    return { statusCode: 400, body: JSON.stringify({ error: 'token, code, and email required' }) };
  }

  try {
    const checkResult = await checkValue(email, code);
    
    if (!checkResult.isCorrect) {
      if (!durable) {
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

    if (durable) {
      console.log('Is a durable handler invocation')
      const command = new SendDurableExecutionCallbackSuccessCommand({
        CallbackId: token,
        Result: JSON.stringify({
          verification: 'ok',
          checkResult
        })
      })
      await lambda.send(command);
    } else {
      const cmd = new SendTaskSuccessCommand({
        taskToken: token,
        output: JSON.stringify({ email, code, checkResult }),
      });

      const result = await sfn.send(cmd);
      console.log('taskToken result', result)
    }

    await deleteTokenEntry(email, token);

    return { statusCode: 200, body: JSON.stringify({ message: 'Verification accepted', checkResult }) };
  } catch (error) {
    console.error('Verification failed:', error);
    
    if (!durable) {
      await sfn.send(new SendTaskFailureCommand({
        taskToken: token,
        cause: error instanceof Error ? error.message : 'Verification failed'
      }))
    } else {
      await lambda.send(new SendDurableExecutionCallbackFailureCommand({
        CallbackId: token,
        Error: {
          ErrorMessage: error instanceof Error ? error.message : 'Verification failed'
        }
      }))
    }
    
    return { statusCode: 400, body: JSON.stringify({ error: error instanceof Error ? error.message : 'Verification failed' }) };
  }
};
