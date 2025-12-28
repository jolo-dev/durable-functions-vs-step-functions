import{SESClient as c,SendEmailCommand as u}from"@aws-sdk/client-ses";import{DynamoDBClient as p,PutItemCommand as f}from"@aws-sdk/client-dynamodb";var g=new c({}),y=new p({}),a=async o=>{console.log("send-email request",o);let{email:e,taskToken:n}=o;if(!e)throw new Error("Missing required fields: email");let r=new Date().toISOString(),t="Demo: Your Verification Code",i=Math.floor(1e5+Math.random()*9e5).toString(),l=`Here is your Code: ${i}`,m=`
    <html>
      <body style="font-family: Arial, sans-serif; text-align: center;">
        <div style="max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
          <h2 style="color: #333;">Verification Required</h2>
          <p>Thank you for using our service. Please use the following code to continue:</p>
          <div style="background-color: #f5f5f5; padding: 15px; border-radius: 4px; margin: 20px 0;">
            <p style="font-size: 24px; font-weight: bold; color: #007bff; margin: 0;">{ token: ${n}, email: ${e}, code: '${i}' }</p>
          </div>
          <p style="font-size: 12px; color: #777;">This code is valid for 15 minutes.</p>
        </div>
      </body>
    </html>
  `;await y.send(new f({TableName:process.env.TABLE_NAME,Item:{id:{S:e},sort:{S:i},status:{S:"pending"},timestamp:{S:r}}}));let d=new u({Source:"johnyscrazy@gmail.com",Destination:{ToAddresses:[e]},Message:{Subject:{Data:t},Body:{Text:{Data:l},Html:{Data:m}}}});try{return await g.send(d),{timestamp:r,taskToken:n,code:i,status:"sent"}}catch(s){throw new Error(`Failed to send email to ${e}: ${s instanceof Error?s.message:"Unknown error"}`)}};var h=()=>Math.floor(1e5+Math.random()*9e5).toString(),b=async o=>{console.log("Step Functions send-email handler:",JSON.stringify(o,null,2));let e=h(),{email:n,taskToken:r}=o;try{return await a({email:n,taskToken:r}),{email:o.email,code:e,status:"email_sent"}}catch(t){throw console.error("Error in step-functions send-email:",t),new Error(`SendEmailFailed: ${t instanceof Error?t.message:"Unknown error"}`)}};export{b as handler};
