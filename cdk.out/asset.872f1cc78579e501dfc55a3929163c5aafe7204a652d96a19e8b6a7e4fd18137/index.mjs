import{SESClient as c,SendEmailCommand as p}from"@aws-sdk/client-ses";import{DynamoDBClient as u,PutItemCommand as f}from"@aws-sdk/client-dynamodb";var y=new c({}),E=new u({}),a=async e=>{console.log("send-email request",e);let{email:o,taskToken:n}=e;if(!o)throw new Error("Missing required fields: email");let i=new Date().toISOString(),r="Demo: Your Verification Code",t=Math.floor(1e5+Math.random()*9e5).toString(),d=`Here is your Code: ${t}`,m=`
    <html>
      <body style="font-family: Arial, sans-serif; text-align: center;">
        <div style="max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
          <h2 style="color: #333;">Verification Required</h2>
          <p>Thank you for using our service. Please use the following code to continue:</p>
          <div style="background-color: #f5f5f5; padding: 15px; border-radius: 4px; margin: 20px 0;">
            <p style="font-size: 24px; font-weight: bold; color: #007bff; margin: 0;">{ token: ${n}, email: ${o}, code: ${t} }</p>
          </div>
          <p style="font-size: 12px; color: #777;">This code is valid for 15 minutes.</p>
        </div>
      </body>
    </html>
  `;await E.send(new f({TableName:process.env.TABLE_NAME,Item:{id:{S:o},sort:{S:t},status:{S:"pending"},timestamp:{S:i}}}));let l=new p({Source:process.env.SENDER_EMAIL,Destination:{ToAddresses:[o]},Message:{Subject:{Data:r},Body:{Text:{Data:d},Html:{Data:m}}}});try{return await y.send(l),{timestamp:i,taskToken:n,code:t,status:"sent"}}catch(s){throw new Error(`Failed to send email to ${o}: ${s instanceof Error?s.message:"Unknown error"}`)}};var S=async e=>{await a({email:e.email,taskToken:e.taskToken})};export{S as handler};
