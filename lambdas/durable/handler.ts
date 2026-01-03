import { checkValue } from "../shared/check-value";
import { sendEmail } from "../shared/send-email"
import { EmailRequest } from "../shared/types"
import {
  DurableLambdaHandler,
  withDurableExecution,
} from "@aws/durable-execution-sdk-js";

export const handler: DurableLambdaHandler = withDurableExecution<EmailRequest>(
  async (event, context) => {
    console.log('durable-handler event', event)
    const { email, taskToken } = event

    if (!taskToken) {
      const result = await context.waitForCallback(
        "wait-for-users-input",
        async (callbackId, ctx) => {
          ctx.logger?.info(`Submitting callback ID to external service: ${callbackId}`);

          const result = await sendEmail({
            email,
            taskToken: callbackId
          });
          ctx.logger.info(`DurableLambdaHandler result ${result}`, result)

          const foundValue = await checkValue(email, result.code)
          ctx.logger.info('DurableLambdaHandler foundValue', foundValue)
        },
        {
          timeout: { minutes: 15 },
        }
      );
      console.log('durable-handler result', result)
      return {
        success: true,
        externalResult: result,
      };
    }

    return {
      success: true
    }
  }
);

