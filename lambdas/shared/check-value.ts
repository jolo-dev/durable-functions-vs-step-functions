import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { CheckValueResult } from './types';

const dynamoClient = new DynamoDBClient({});

export const checkValue = async (requestId: string): Promise<CheckValueResult> => {
// Get item from DynamoDB
  const getItemResult = await dynamoClient.send(new GetItemCommand({
    TableName: process.env.TABLE_NAME!,
    Key: {
      id: { S: requestId },
      sort: { S: '0' } // Default sort key for email items
    }
  }));

  if (!getItemResult.Item) {
    throw new Error(`Request ${requestId} not found`);
  }
  
  const item = getItemResult.Item;
  const status = item.status?.S || 'unknown';
  const timestamp = item.timestamp?.S || '';

  // Simulate validation logic - check if status is correct
  const isCorrect = status === 'success';
  
  // Update item with check result
  await dynamoClient.send(new UpdateItemCommand({
    TableName: process.env.TABLE_NAME!,
    Key: {
      id: { S: requestId },
      sort: { S: '0' }
    },
    UpdateExpression: 'SET #status = :status, #checked = :checked, #result = :result',
    ExpressionAttributeNames: {
      '#status': 'status'
    },
    ExpressionAttributeValues: {
      ':status': { S: isCorrect ? 'success' : 'incorrect' },
      ':checked': { S: new Date().toISOString() },
      ':result': { S: isCorrect.toString() }
    }
  }));
  
  return {
    requestId,
    status,
    timestamp,
    isCorrect,
    checkResult: isCorrect ? 'success' : 'incorrect',
    checkedAt: new Date().toISOString()
  };
};