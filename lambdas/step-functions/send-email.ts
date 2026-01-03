import { sendEmail } from '../shared/send-email';
import { EmailRequest, SendEmailResult } from '../shared/types';

const generateCode = (): string => Math.floor(100000 + Math.random() * 900000).toString();

export const handler = async (event: EmailRequest): Promise<SendEmailResult> => {
  console.log('Step Functions send-email handler:', JSON.stringify(event, null, 2));

  const code = generateCode();
  const { email, taskToken } = event;

  try {
    const result = await sendEmail({
      email,
      taskToken
    });

    return {
      ...result,
      code
    };
  } catch (error) {
    console.error('Error in step-functions send-email:', error);
    throw new Error(`SendEmailFailed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
};
