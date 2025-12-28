import{SESClient as c,SendEmailCommand as u}from"@aws-sdk/client-ses";import{DynamoDBClient as p,PutItemCommand as f}from"@aws-sdk/client-dynamodb";var g=new c({}),y=new p({}),w=async n=>{let{email:e,requestId:i,code:r}=n;if(!e)throw new Error("Missing required fields: to, requestId, code");let s=new Date().toISOString(),a="Demo: Your Verification Code",t=r||Math.floor(1e5+Math.random()*9e5).toString(),d=`Here is your Code: ${t}`,m=`
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
  `;await y.send(new f({TableName:process.env.TABLE_NAME,Item:{id:{S:e},sort:{S:t},status:{S:"pending"},timestamp:{S:s}}}));let l=new u({Source:process.env.SENDER_EMAIL,Destination:{ToAddresses:[e]},Message:{Subject:{Data:a},Body:{Text:{Data:d},Html:{Data:m}}}});try{let o=await g.send(l);return{requestId:i,code:t,messageId:o.MessageId,timestamp:s,status:"sent"}}catch(o){throw new Error(`Failed to send email to ${e}: ${o instanceof Error?o.message:"Unknown error"}`)}};export{w as sendEmail};
