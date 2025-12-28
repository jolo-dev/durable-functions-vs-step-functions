import{SESClient as l,SendEmailCommand as c}from"@aws-sdk/client-ses";import{DynamoDBClient as u,PutItemCommand as p}from"@aws-sdk/client-dynamodb";var f=new l({}),g=new u({}),S=async n=>{let{to:i,requestId:t}=n;if(!i||!t)throw new Error("Missing required fields: to, requestId, code");let s=new Date().toISOString(),r="Demo: Your Verification Code",o=Math.floor(1e5+Math.random()*9e5).toString(),a=`Here is your Code: ${o}`,d=`
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
  `;await g.send(new p({TableName:process.env.TABLE_NAME,Item:{id:{S:email},sort:{S:o},requestId:{S:t},status:{S:"pending"},timestamp:{S:s}}}));let m=new c({Source:process.env.SENDER_EMAIL,Destination:{ToAddresses:[email]},Message:{Subject:{Data:r},Body:{Text:{Data:a},Html:{Data:d}}}});try{let e=await f.send(m);return{requestId:t,messageId:e.MessageId,timestamp:s,status:"sent"}}catch(e){throw new Error(`Failed to send email to ${email}: ${e instanceof Error?e.message:"Unknown error"}`)}};export{S as sendEmail};
