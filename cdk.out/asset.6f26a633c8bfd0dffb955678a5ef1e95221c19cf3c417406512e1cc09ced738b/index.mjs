import{SESClient as c,SendEmailCommand as p}from"@aws-sdk/client-ses";import{DynamoDBClient as u,PutItemCommand as f}from"@aws-sdk/client-dynamodb";var y=new c({}),E=new u({}),r=async t=>{console.log("send-email request",t);let{email:e,taskToken:n}=t;if(!e||!n)throw new Error("Missing required fields: email or taskToken");let s=new Date().toISOString(),a="Demo: Your Verification Code",o=Math.floor(1e5+Math.random()*9e5).toString(),d=`Here is your Code: ${o}`,m=`
    <html>
      <body style="font-family: Arial, sans-serif; text-align: center;">
        <div style="max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
          <h2 style="color: #333;">Verification Required</h2>
          <p>Thank you for using our service. Please use the following code to continue:</p>
          <div style="background-color: #f5f5f5; padding: 15px; border-radius: 4px; margin: 20px 0;">
            <p style="font-size: 24px; font-weight: bold; color: #007bff; margin: 0;">{ token: ${o}, email: ${e}, code: ${o} }</p>
          </div>
          <p style="font-size: 12px; color: #777;">This code is valid for 15 minutes.</p>
        </div>
      </body>
    </html>
  `;await E.send(new f({TableName:process.env.TABLE_NAME,Item:{id:{S:e},sort:{S:o},status:{S:"pending"},timestamp:{S:s}}}));let l=new p({Source:process.env.SENDER_EMAIL,Destination:{ToAddresses:[e]},Message:{Subject:{Data:a},Body:{Text:{Data:d},Html:{Data:m}}}});try{return await y.send(l),{timestamp:s,taskToken:n,code:o,status:"sent"}}catch(i){throw new Error(`Failed to send email to ${e}: ${i instanceof Error?i.message:"Unknown error"}`)}};var S=async(t,e)=>{let{email:n,taskToken:s}=t;await r({email:n,taskToken:s})};export{S as handler};
