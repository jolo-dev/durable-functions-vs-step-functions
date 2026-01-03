import { checkValue } from '../shared/check-value';
import { APIGatewayProxyHandlerV2 } from 'aws-lambda';
import { CheckValueInput, LambdaResponse } from '../shared/types';

export const handler: APIGatewayProxyHandlerV2 = async (event): Promise<LambdaResponse> => {
  console.log('Step Functions check-value handler:', JSON.stringify(event, null, 2));

  const body: CheckValueInput = typeof event.body === 'string' ? JSON.parse(event.body || '{}') : event.body || {};
  const { email, code } = body;

  if (!email || !code) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Missing email or code' })
    };
  }

  try {
    const result = await checkValue(email, code);
    return {
      statusCode: 200,
      body: JSON.stringify(result)
    };
  } catch (error) {
    console.error('Error in step-functions check-value:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({
        error: 'Failed to check value',
        details: error instanceof Error ? error.message : 'Unknown error'
      })
    };
  }
};
