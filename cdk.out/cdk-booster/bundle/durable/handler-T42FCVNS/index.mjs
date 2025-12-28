import{SESClient as u,SendEmailCommand as c}from"@aws-sdk/client-ses";import{DynamoDBClient as p,PutItemCommand as f}from"@aws-sdk/client-dynamodb";var g=new u({}),y=new p({}),d=async o=>{console.log("send-email request",o);let{email:e,taskToken:n}=o;if(!e)throw new Error("Missing required fields: email");let r=new Date().toISOString(),s="Demo: Your Verification Code",t=Math.floor(1e5+Math.random()*9e5).toString(),a=`Here is your Code: ${t}`,i=`
    <html>
      <body style="font-family: Arial, sans-serif; text-align: center;">
        <div style="max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
          <h2 style="color: #333;">Verification Required</h2>
          <p>Thank you for using our service. Please use the following code to continue:</p>
          <div style="background-color: #f5f5f5; padding: 15px; border-radius: 4px; margin: 20px 0;">
            <p style="font-size: 24px; font-weight: bold; color: #007bff; margin: 0;">{ token: ${n}, email: ${e}, code: '${t}' }</p>
          </div>
          <p style="font-size: 12px; color: #777;">This code is valid for 15 minutes.</p>
        </div>
      </body>
    </html>
  `;await y.send(new f({TableName:process.env.TABLE_NAME,Item:{id:{S:e},sort:{S:t},status:{S:"pending"},timestamp:{S:r}}}));let m=new c({Source:"johnyscrazy@gmail.com",Destination:{ToAddresses:[e]},Message:{Subject:{Data:s},Body:{Text:{Data:a},Html:{Data:i}}}});try{return await g.send(m),{timestamp:r,taskToken:n,code:t,status:"sent"}}catch(l){throw new Error(`Failed to send email to ${e}: ${l instanceof Error?l.message:"Unknown error"}`)}};var E=async(o,e)=>{console.log("durable-handler event",o);let{email:n,taskToken:r}=o;if(!r){let s=await e.waitForCallback("wait-for-users-input",async(t,a)=>{a.logger?.info(`Submitting callback ID to external service: ${t}`);let i=await d({email:n,taskToken:t});a.logger.info("durable-handler result",i)},{timeout:{minutes:15}});return console.log("durable-handler result",s),{success:!0,externalResult:s}}return{success:!0}};export{E as handler};
