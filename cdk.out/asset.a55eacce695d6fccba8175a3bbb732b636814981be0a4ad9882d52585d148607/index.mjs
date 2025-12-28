import{SESClient as u,SendEmailCommand as p}from"@aws-sdk/client-ses";import{DynamoDBClient as f,PutItemCommand as g}from"@aws-sdk/client-dynamodb";var h=new u({}),y=new f({}),a=async t=>{let{email:e,requestId:s,code:o}=t;if(!e)throw new Error("Missing required fields: to, requestId, code");let i=new Date().toISOString(),d="Demo: Your Verification Code",n=Math.floor(1e5+Math.random()*9e5).toString(),l=`Here is your Code: ${n}`,m=`
    <html>
      <body style="font-family: Arial, sans-serif; text-align: center;">
        <div style="max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
          <h2 style="color: #333;">Verification Required</h2>
          <p>Thank you for using our service. Please use the following code to continue:</p>
          <div style="background-color: #f5f5f5; padding: 15px; border-radius: 4px; margin: 20px 0;">
            <p style="font-size: 24px; font-weight: bold; color: #007bff; margin: 0;">${n}</p>
          </div>
          <p style="font-size: 12px; color: #777;">This code is valid for 15 minutes.</p>
        </div>
      </body>
    </html>
  `;await y.send(new g({TableName:process.env.TABLE_NAME,Item:{id:{S:e},sort:{S:n},status:{S:"pending"},timestamp:{S:i}}}));let c=new p({Source:process.env.SENDER_EMAIL,Destination:{ToAddresses:[e]},Message:{Subject:{Data:d},Body:{Text:{Data:l},Html:{Data:m}}}});try{return{messageId:(await h.send(c)).MessageId,timestamp:i,status:"sent"}}catch(r){throw new Error(`Failed to send email to ${e}: ${r instanceof Error?r.message:"Unknown error"}`)}};var E=()=>Math.floor(1e5+Math.random()*9e5).toString(),b=async t=>{console.log("Step Functions send-email handler:",JSON.stringify(t,null,2));let e=`req-${Date.now()}`,s=E();try{return await a({email:t.email}),{email:t.email,requestId:e,code:s,status:"email_sent"}}catch(o){throw console.error("Error in step-functions send-email:",o),new Error(`SendEmailFailed: ${o instanceof Error?o.message:"Unknown error"}`)}};export{b as handler};
