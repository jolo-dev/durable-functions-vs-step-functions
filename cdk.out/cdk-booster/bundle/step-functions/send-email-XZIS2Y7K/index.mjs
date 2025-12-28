import{SESClient as u,SendEmailCommand as p}from"@aws-sdk/client-ses";import{DynamoDBClient as f,PutItemCommand as g}from"@aws-sdk/client-dynamodb";var h=new u({}),y=new f({}),a=async t=>{let{email:e,requestId:n,code:o}=t;if(!e)throw new Error("Missing required fields: to, requestId, code");let i=new Date().toISOString(),d="Demo: Your Verification Code",r=o||Math.floor(1e5+Math.random()*9e5).toString(),l=`Here is your Code: ${r}`,m=`
    <html>
      <body style="font-family: Arial, sans-serif; text-align: center;">
        <div style="max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
          <h2 style="color: #333;">Verification Required</h2>
          <p>Thank you for using our service. Please use the following code to continue:</p>
          <div style="background-color: #f5f5f5; padding: 15px; border-radius: 4px; margin: 20px 0;">
            <p style="font-size: 24px; font-weight: bold; color: #007bff; margin: 0;">${r}</p>
          </div>
          <p style="font-size: 12px; color: #777;">This code is valid for 15 minutes.</p>
        </div>
      </body>
    </html>
  `;await y.send(new g({TableName:process.env.TABLE_NAME,Item:{id:{S:e},sort:{S:r},status:{S:"pending"},timestamp:{S:i}}}));let c=new p({Source:process.env.SENDER_EMAIL,Destination:{ToAddresses:[e]},Message:{Subject:{Data:d},Body:{Text:{Data:l},Html:{Data:m}}}});try{let s=await h.send(c);return{requestId:n,code:r,messageId:s.MessageId,timestamp:i,status:"sent"}}catch(s){throw new Error(`Failed to send email to ${e}: ${s instanceof Error?s.message:"Unknown error"}`)}};var E=()=>Math.floor(1e5+Math.random()*9e5).toString(),b=async t=>{console.log("Step Functions send-email handler:",JSON.stringify(t,null,2));let e=`req-${Date.now()}`,n=E();try{return await a({email:t.email,requestId:e,code:n}),{email:t.email,requestId:e,code:n,status:"email_sent"}}catch(o){throw console.error("Error in step-functions send-email:",o),new Error(`SendEmailFailed: ${o instanceof Error?o.message:"Unknown error"}`)}};export{b as handler};
