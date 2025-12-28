import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';

const dynamoClient = new DynamoDBClient({});

const MAX_WAIT_TIME = 900; // 15 minutes in seconds

export const waitForSignal = async (
  requestId: string,
  taskToken?: string,
  maxWaitTime: number = MAX_WAIT_TIME
): Promise<{ received: boolean; value?: unknown }> => {
  const startTime = Date.now();

  while (Date.now() - startTime < maxWaitTime * 1000) {
    // Check DynamoDB for signal
    const result = await dynamoClient.send(new GetItemCommand({
      TableName: process.env.TABLE_NAME!,
      Key: {
        id: { S: requestId },
        sort: { S: '0' } // Use a fixed sort key for signals
      }
    }));

    if (result.Item && result.Item.signal?.S) {
      return {
        received: true,
        value: JSON.parse(result.Item.signal.S)
      };
    }

    // Wait before checking again
    await new Promise(resolve => setTimeout(resolve, 2000)); // Check every 2 seconds
  }

  return { received: false };
};

export const sendTaskSuccess = async (taskToken: string, result: unknown) => {
  // This would be called by external signal handler
  // Implementation depends on Step Functions callback mechanism
  console.log(`Task success for token ${taskToken}:`, result);
};

export const storeTaskToken = async (requestId: string, taskToken: string) => {
  await dynamoClient.send(new UpdateItemCommand({
    TableName: process.env.TABLE_NAME!,
    Key: {
      email: { S: requestId },
      code: { N: '0' } // Use a fixed code for signals
    },
    UpdateExpression: 'SET taskToken = :token',
    ExpressionAttributeValues: {
      ':token': { S: taskToken }
    }
  }));
};
