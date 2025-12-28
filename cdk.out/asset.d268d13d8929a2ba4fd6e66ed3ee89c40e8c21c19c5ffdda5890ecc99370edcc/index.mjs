import{SESClient as l,SendEmailCommand as c}from"@aws-sdk/client-ses";import{DynamoDBClient as u,PutItemCommand as p}from"@aws-sdk/client-dynamodb";var f=new l({}),y=new u({}),w=async i=>{let{to:e,requestId:s,code:t}=i;if(!e||!s||!t)throw new Error("Missing required fields: to, requestId, code");let n=new Date().toISOString(),r="Demo: Your Verification Code",a=`Here is your Code: ${t}`,d=`
    <html>
      <body style="font-family: Arial, sans-serif; text-align: center;">
        <div style="max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
          <h2 style="color: #333;">Verification Required</h2>
          <p>Thank you for using our service. Please use the following code to continue:</p>
          <div style="background-color: #f5f5f5; padding: 15px; border-radius: 4px; margin: 20px 0;">
            <p style="font-size: 24px; font-weight: bold; color: #007bff; margin: 0;">${t}</p>
          </div>
          <p style="font-size: 12px; color: #777;">This code is valid for 15 minutes.</p>
        </div>
      </body>
    </html>
  `;await y.send(new p({TableName:process.env.TABLE_NAME,Item:{id:{S:e},sort:{S:t},requestId:{S:s},status:{S:"pending"},timestamp:{S:n}}}));let m=new c({Source:process.env.SENDER_EMAIL,Destination:{ToAddresses:[e]},Message:{Subject:{Data:r},Body:{Text:{Data:a},Html:{Data:d}}}});try{let o=await f.send(m);return{requestId:s,messageId:o.MessageId,timestamp:n,status:"sent"}}catch(o){throw new Error(`Failed to send email to ${e}: ${o instanceof Error?o.message:"Unknown error"}`)}};export{w as sendEmail};
