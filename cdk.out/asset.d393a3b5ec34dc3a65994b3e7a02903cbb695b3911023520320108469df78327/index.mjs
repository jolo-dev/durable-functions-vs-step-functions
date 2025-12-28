import{SESClient as m,SendEmailCommand as l}from"@aws-sdk/client-ses";import{DynamoDBClient as c,PutItemCommand as u}from"@aws-sdk/client-dynamodb";var p=new m({}),f=new c({}),E=async n=>{let{email:e}=n;if(!e)throw new Error("Missing required fields: to, requestId, code");let s=new Date().toISOString(),r="Demo: Your Verification Code",o=Math.random(),i=`Here is your Code: ${o}`,a=`
    <html>
      <body style="font-family: Arial, sans-serif; text-align: center;">
        <div style="max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
          <h2 style="color: #333;">Verification Required</h2>
          <p>Thank you for using our service. Please use the following code to continue:</p>
          <div style="background-color: #f5f5f5; padding: 15px; border-radius: 4px; margin: 20px 0;">
            <p style="font-size: 24px; font-weight: bold; color: #007bff; margin: 0;">${o}</p>
          </div>
          <p style="font-size: 12px; color: #777;">This code is valid for 15 minutes.</p>
        </div>
      </body>
    </html>
  `;await f.send(new u({TableName:process.env.TABLE_NAME,Item:{id:{S:e},sort:{S:o},requestId:{S:requestId},status:{S:"pending"},timestamp:{S:s}}}));let d=new l({Source:process.env.SENDER_EMAIL,Destination:{ToAddresses:[e]},Message:{Subject:{Data:r},Body:{Text:{Data:i},Html:{Data:a}}}});try{let t=await p.send(d);return{requestId,messageId:t.MessageId,timestamp:s,status:"sent"}}catch(t){throw new Error(`Failed to send email to ${e}: ${t instanceof Error?t.message:"Unknown error"}`)}};export{E as sendEmail};
