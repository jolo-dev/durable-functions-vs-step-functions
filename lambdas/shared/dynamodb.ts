import { DynamoDBClient, GetItemCommand, PutItemCommand, UpdateItemCommand, DeleteItemCommand } from '@aws-sdk/client-dynamodb';

const dynamoClient = new DynamoDBClient({});

export const putVerificationCode = async (email: string, code: string, timestamp: string): Promise<void> => {
  await dynamoClient.send(new PutItemCommand({
    TableName: process.env.TABLE_NAME!,
    Item: {
      id: { S: email },
      sort: { S: code },
      status: { S: 'pending' },
      timestamp: { S: timestamp }
    }
  }));
};

export const getVerificationCode = async (email: string, code: string) => {
  const result = await dynamoClient.send(new GetItemCommand({
    TableName: process.env.TABLE_NAME!,
    Key: {
      id: { S: email },
      sort: { S: code }
    }
  }));

  if (!result.Item) {
    throw new Error(`Verification code not found for email ${email}`);
  }

  return {
    status: result.Item.status?.S || 'unknown',
    timestamp: result.Item.timestamp?.S || ''
  };
};

export const updateVerificationStatus = async (email: string, code: string, isCorrect: boolean): Promise<void> => {
  await dynamoClient.send(new UpdateItemCommand({
    TableName: process.env.TABLE_NAME!,
    Key: {
      id: { S: email },
      sort: { S: code }
    },
    UpdateExpression: 'SET #status = :status, #checked = :checked, #result = :result',
    ExpressionAttributeNames: {
      '#status': 'status',
      '#checked': 'checked',
      '#result': 'result'
    },
    ExpressionAttributeValues: {
      ':status': { S: isCorrect ? 'verified' : 'failed' },
      ':checked': { S: new Date().toISOString() },
      ':result': { S: isCorrect.toString() }
    }
  }));
};

export const deleteTokenEntry = async (email: string, token: string): Promise<void> => {
  await dynamoClient.send(new DeleteItemCommand({
    TableName: process.env.TABLE_NAME!,
    Key: {
      id: { S: email },
      sort: { S: token }
    }
  }));
};