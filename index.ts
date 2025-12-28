import { App } from 'aws-cdk-lib';
import { DurableFunctionsVsStepFunctionsStack } from './infra/stack';

const app = new App();

new DurableFunctionsVsStepFunctionsStack(app, 'DurableFunctionsVsStepFunctions', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  },
});
