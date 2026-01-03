import { EmailIdentity, Identity } from 'aws-cdk-lib/aws-ses';
import { Stack, CfnOutput, type StackProps, Duration, RemovalPolicy } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import {
  Table,
  AttributeType,
  BillingMode
} from 'aws-cdk-lib/aws-dynamodb';
import {
  Runtime,
} from 'aws-cdk-lib/aws-lambda';
import {
  CfnStage,
  HttpApi,
  HttpMethod,
  MappingValue,
  ParameterMapping
} from 'aws-cdk-lib/aws-apigatewayv2';
import {
  HttpLambdaIntegration,
  HttpStepFunctionsIntegration
} from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import {
  StateMachine,
  DefinitionBody,
  Choice,
  Condition,
  Succeed,
  Fail,
  JsonPath,
  IntegrationPattern,
  TaskInput,
} from 'aws-cdk-lib/aws-stepfunctions';
import {
  LambdaInvoke
} from 'aws-cdk-lib/aws-stepfunctions-tasks';
import { NodejsFunction, OutputFormat } from 'aws-cdk-lib/aws-lambda-nodejs';
import { PolicyStatement } from 'aws-cdk-lib/aws-iam';
import { LogGroup } from 'aws-cdk-lib/aws-logs';

export class DurableFunctionsVsStepFunctionsStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // DynamoDB table for state management
    const stateTable = new Table(this, 'StateTable', {
      tableName: 'MagicCode',
      partitionKey: {
        name: 'id',
        type: AttributeType.STRING
      },
      sortKey: {
        name: 'sort',
        type: AttributeType.STRING // Additional sort key for email items
      },
      billingMode: BillingMode.PAY_PER_REQUEST,
      removalPolicy: RemovalPolicy.DESTROY
    });

    // SES for sending emails
    const senderEmail = process.env.SENDER || 'johnyscrazy@gmail.com';

    const emailIdentity = new EmailIdentity(this, 'SenderIdentity', {
      identity: Identity.email(senderEmail),
    });

    // StateMachine
    const choiceStep = new Choice(this, 'IsCodeCorrect?')
      .when(Condition.stringEquals(JsonPath.stringAt('$.verification'), 'ok'), new Succeed(this, 'Success'))
      .otherwise(new Fail(this, 'IncorrectCode', {
        cause: 'Verification code did not match',
        error: 'IncorrectCode'
      }));

    const stepSendEmail = new NodejsFunction(this, 'StepSendEmail', {
      functionName: 'step-send-email',
      runtime: Runtime.NODEJS_24_X,
      entry: 'lambdas/step-functions/send-email.ts',
      bundling: {
        format: OutputFormat.ESM,
        minify: true,
      },
      environment: {
        TABLE_NAME: stateTable.tableName,
        SENDER_EMAIL: senderEmail
      },
      timeout: Duration.seconds(30)
    });
    stateTable.grantWriteData(stepSendEmail);
    emailIdentity.grantSendEmail(stepSendEmail);

    const sendEmailStep = new LambdaInvoke(this, 'SendEmailStep', {
      lambdaFunction: stepSendEmail,
      integrationPattern: IntegrationPattern.WAIT_FOR_TASK_TOKEN,
      payload:
        TaskInput.fromObject({
          email: JsonPath.stringAt('$.email'),
          taskToken: JsonPath.taskToken,
        })
    });

    // Define the state machine with task token pattern
    const definition = sendEmailStep
      .next(choiceStep); // Check if the received code matches the original code

    const stateMachine = new StateMachine(this, 'EmailStateMachine', {
      stateMachineName: 'EmailProcessingWorkflow',
      definitionBody: DefinitionBody.fromChainable(definition),
      timeout: Duration.minutes(15) // Match task token timeout
    });

    // Durable Handler
    const durableHandler = new NodejsFunction(this, 'DurableHandler', {
      functionName: 'durable-handler',
      runtime: Runtime.NODEJS_24_X,
      entry: 'lambdas/durable/handler.ts',
      bundling: {
        format: OutputFormat.ESM,
        minify: true,
      },
      durableConfig: {
        executionTimeout: Duration.minutes(15)
      },
      environment: {
        TABLE_NAME: stateTable.tableName,
      },
    });

    stateTable.grantReadWriteData(durableHandler);
    emailIdentity.grantSendEmail(durableHandler)

    const durableInvoker = new NodejsFunction(this, 'DurableInvoker', {
      functionName: 'durable-invoker',
      runtime: Runtime.NODEJS_24_X,
      entry: 'lambdas/durable/invoker.ts',
      bundling: {
        format: OutputFormat.ESM,
        minify: true,
      },
      environment: {
        FUNCTION_ARN: durableHandler.functionArn,
      },
    });

    durableHandler.grantInvoke(durableInvoker);
    // End Durable Handler
    const tokenHandler = new NodejsFunction(this, 'TokenHandler', {
      functionName: 'token-handler',
      runtime: Runtime.NODEJS_24_X,
      entry: 'lambdas/shared/token-handler.ts',
      environment: {
        TABLE_NAME: stateTable.tableName,
        DURABLE_FUNCTION: durableHandler.functionArn
      },
      bundling: {
        bundleAwsSDK: true,
        format: OutputFormat.ESM,
        minify: true,
        mainFields: ['module', 'main']
      },
      initialPolicy: [
        new PolicyStatement({
          actions: ['states:SendTaskSuccess'],
          resources: [stateMachine.stateMachineArn]
        }),
      ],
    });
    tokenHandler.addToRolePolicy(new PolicyStatement({
      actions: [
        'lambda:SendDurableExecutionCallbackSuccess',
        'lambda:SendDurableExecutionCallbackFailure'
      ],
      resources: [`${durableHandler.functionArn}:*`, durableHandler.functionArn]
    }))
    stateTable.grantReadWriteData(tokenHandler);
    // HTTP API
    const httpApi = new HttpApi(this, 'EmailHttpApi', {
      apiName: 'Email Service API',
      description: 'HTTP API for email processing with durable and step functions',
    });

    // Little hack to add logs: https://github.com/aws/aws-cdk/issues/11100#issuecomment-782213423
    const logs = new LogGroup(this, `${id}-logs`, {
      logGroupName: `/aws/vendedlogs/aws-apigatewayv2/${id}/logs`,
      removalPolicy: RemovalPolicy.DESTROY
    });
    const stage = httpApi.defaultStage?.node.defaultChild as CfnStage;
    stage.accessLogSettings = {
      destinationArn: logs.logGroupArn,
      format: JSON.stringify({
        requestId: "$context.requestId",
        ip: "$context.identity.sourceIp",
        caller: "$context.identity.caller",
        user: "$context.identity.user",
        requestTime: "$context.requestTime",
        httpMethod: "$context.httpMethod",
        resourcePath: "$context.resourcePath",
        status: "$context.status",
        protocol: "$context.protocol",
        responseLength: "$context.responseLength",
      }),
    };
    // API Gateway Routes - /steps correctly configured with StepFunctions integration
    httpApi.addRoutes({
      path: '/steps',
      methods: [HttpMethod.POST],
      integration: new HttpStepFunctionsIntegration('StepsIntegration', {
        stateMachine,
        parameterMapping: ParameterMapping.fromObject({
          Input: MappingValue.custom('$request.body'),
          StateMachineArn: MappingValue.custom(stateMachine.stateMachineArn)
        })
      })
    });

    // Durable path - single orchestrator
    httpApi.addRoutes({
      path: '/durable',
      methods: [HttpMethod.POST],
      integration: new HttpLambdaIntegration('DurableIntegration', durableInvoker)
    });

    // Token endpoint - unified for both paths
    httpApi.addRoutes({
      path: '/token',
      methods: [HttpMethod.POST],
      integration: new HttpLambdaIntegration('Token', tokenHandler)
    });

    // Output important values
    new CfnOutput(this, 'ApiUrl', {
      value: httpApi.url ?? ''
    });

    new CfnOutput(this, 'StateMachineArn', {
      value: stateMachine.stateMachineArn
    });
  }
}
