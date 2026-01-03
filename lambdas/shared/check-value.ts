import { CheckValueResult } from './types';
import { getVerificationCode, updateVerificationStatus } from './dynamodb';

export const checkValue = async (email: string, code: string): Promise<CheckValueResult> => {
  const { status, timestamp } = await getVerificationCode(email, code);
  
  const isCorrect = status === 'pending';
  
  await updateVerificationStatus(email, code, isCorrect);
  
  return {
    requestId: `${email}#${code}`,
    status,
    timestamp,
    isCorrect,
    checkResult: isCorrect ? 'verified' : 'failed',
    checkedAt: new Date().toISOString()
  };
};