import{SESClient as m,SendEmailCommand as l}from"@aws-sdk/client-ses";import{DynamoDBClient as c,PutItemCommand as p}from"@aws-sdk/client-dynamodb";var u=new m({}),f=new c({}),E=async s=>{let{email:e}=s;if(!e)throw new Error("Missing required fields: to, requestId, code");let n=new Date().toISOString(),i="Demo: Your Verification Code",t=Math.floor(1e5+Math.random()*9e5).toString(),r=`Here is your Code: ${t}`,a=`
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
  `;await f.send(new p({TableName:process.env.TABLE_NAME,Item:{id:{S:e},sort:{S:t},status:{S:"pending"},timestamp:{S:n}}}));let d=new l({Source:process.env.SENDER_EMAIL,Destination:{ToAddresses:[e]},Message:{Subject:{Data:i},Body:{Text:{Data:r},Html:{Data:a}}}});try{let o=await u.send(d);return{timestamp:n,status:"sent"}}catch(o){throw new Error(`Failed to send email to ${e}: ${o instanceof Error?o.message:"Unknown error"}`)}};export{E as sendEmail};
