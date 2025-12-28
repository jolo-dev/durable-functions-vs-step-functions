import { checkValue } from '../shared/check-value';
import { SendEmailResult } from '../shared/types';

export const handler = async (event: SendEmailResult) => {
  console.log('Step Functions check-value handler:', JSON.stringify(event, null, 2));

  const { code } = event;
  if (!code) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Missing requestId' })
    };
  }

  try {
    const result = await checkValue(code);
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
