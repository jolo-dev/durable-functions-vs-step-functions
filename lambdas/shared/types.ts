export interface EmailRequest {
  email: string;
  taskToken?: string;
}

export interface DurableInput extends EmailRequest {
  // Additional durable-specific fields if needed
}

export interface LambdaResponse {
  statusCode: number;
  body: string;
}

export interface SendEmailResult {
  timestamp: string;
  status: string;
  taskToken?: string;
  code: string;
}

export interface CheckValueResult {
  requestId: string;
  status: string;
  timestamp: string;
  isCorrect: boolean;
  checkResult: string;
  checkedAt: string;
}

export interface TokenEvent {
  body: TokenRequestBody;
}

export interface TokenRequestBody {
  token: string;
  code: string;
  email: string;
  durable?: boolean;
}

export interface InvokerBody {
  email: string;
}



export interface CheckValueInput {
  email: string;
  code: string;
}
