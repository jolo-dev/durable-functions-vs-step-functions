import{SESClient as c,SendEmailCommand as u}from"@aws-sdk/client-ses";import{DynamoDBClient as p,PutItemCommand as f}from"@aws-sdk/client-dynamodb";var g=new c({}),h=new p({}),i=async o=>{console.log("send-email request",o);let{email:e,taskToken:n}=o;if(!e||!n)throw new Error("Missing required fields: email or taskToken");let t=new Date().toISOString(),a="Demo: Your Verification Code",r=Math.floor(1e5+Math.random()*9e5).toString(),l=`Here is your Code: ${r}`,d=`
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
  `;await h.send(new f({TableName:process.env.TABLE_NAME,Item:{id:{S:e},sort:{S:r},status:{S:"pending"},timestamp:{S:t}}}));let m=new u({Source:process.env.SENDER_EMAIL,Destination:{ToAddresses:[e]},Message:{Subject:{Data:a},Body:{Text:{Data:l},Html:{Data:d}}}});try{return await g.send(m),{timestamp:t,taskToken:n,status:"sent"}}catch(s){throw new Error(`Failed to send email to ${e}: ${s instanceof Error?s.message:"Unknown error"}`)}};var y=()=>Math.floor(1e5+Math.random()*9e5).toString(),b=async o=>{console.log("Step Functions send-email handler:",JSON.stringify(o,null,2));let e=`req-${Date.now()}`,n=y();try{return await i({email:o.email,requestId:e,code:n}),{email:o.email,requestId:e,code:n,status:"email_sent"}}catch(t){throw console.error("Error in step-functions send-email:",t),new Error(`SendEmailFailed: ${t instanceof Error?t.message:"Unknown error"}`)}};export{b as handler};
