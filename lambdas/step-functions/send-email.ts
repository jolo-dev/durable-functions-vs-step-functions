import { sendEmail } from '../shared/send-email';
import { EmailRequest } from '../shared/types';

const generateCode = (): string => Math.floor(100000 + Math.random() * 900000).toString();

export const handler = async (event: EmailRequest) => {
  console.log('Step Functions send-email handler:', JSON.stringify(event, null, 2));

  const code = generateCode();
  const { email, taskToken } = event
  try {
    // The request for sendEmail now includes the generated code and requestId
    await sendEmail({
      email,
      taskToken
    });

    // Return the state for the next step (Wait For Signal)
    return {
      email: event.email,
      code,
      status: 'email_sent'
    };
  } catch (error) {
    console.error('Error in step-functions send-email:', error);
    throw new Error(`SendEmailFailed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
};
