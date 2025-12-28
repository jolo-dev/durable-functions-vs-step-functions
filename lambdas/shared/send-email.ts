import { SESClient, SendEmailCommand } from '@aws-sdk/client-ses';
import { DynamoDBClient, PutItemCommand } from '@aws-sdk/client-dynamodb';
import { EmailRequest, SendEmailResult } from './types';

const sesClient = new SESClient({});
const dynamoClient = new DynamoDBClient({});

export const sendEmail = async (request: EmailRequest): Promise<SendEmailResult> => {
  console.log('send-email request', request)
  const { email, taskToken } = request;

  if (!email) {
    throw new Error('Missing required fields: email');
  }

  const timestamp = new Date().toISOString();
  const subject = 'Demo: Your Verification Code'
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const textBody = `Here is your Code: ${code}`
  const htmlBody = `
    <html>
      <body style="font-family: Arial, sans-serif; text-align: center;">
        <div style="max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
          <h2 style="color: #333;">Verification Required</h2>
          <p>Thank you for using our service. Please use the following code to continue:</p>
          <div style="background-color: #f5f5f5; padding: 15px; border-radius: 4px; margin: 20px 0;">
            <p style="font-size: 24px; font-weight: bold; color: #007bff; margin: 0;">{ token: ${taskToken}, email: ${email}, code: '${code}' }</p>
          </div>
          <p style="font-size: 12px; color: #777;">This code is valid for 15 minutes.</p>
        </div>
      </body>
    </html>
  `;

  // Store request in DynamoDB
  // Partition Key: email address, Sort Key: code
  await dynamoClient.send(new PutItemCommand({
    TableName: process.env.TABLE_NAME!,
    Item: {
      id: { S: email }, // Use email as partition key
      sort: { S: code }, // Use code as sort key for verification
      status: { S: 'pending' },
      timestamp: { S: timestamp }
    }
  }));

  // Send email via SES
  const sendEmailCommand = new SendEmailCommand({
    Source: 'johnyscrazy@gmail.com',
    Destination: {
      ToAddresses: [email]
    },
    Message: {
      Subject: { Data: subject },
      Body: {
        Text: { Data: textBody },
        Html: { Data: htmlBody }
      }
    }
  });

  try {
    await sesClient.send(sendEmailCommand);

    return {
      timestamp,
      taskToken,
      code,
      status: 'sent'
    };
  } catch (error) {
    throw new Error(`Failed to send email to ${email}: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
};
