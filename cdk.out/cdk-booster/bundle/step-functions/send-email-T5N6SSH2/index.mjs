import{SESClient as c,SendEmailCommand as p}from"@aws-sdk/client-ses";import{DynamoDBClient as u,PutItemCommand as f}from"@aws-sdk/client-dynamodb";var g=new c({}),E=new u({}),a=async e=>{console.log("send-email request",e);let{email:o,taskToken:t}=e;if(!o||!t)throw new Error("Missing required fields: email or taskToken");let r=new Date().toISOString(),n="Demo: Your Verification Code",s=Math.floor(1e5+Math.random()*9e5).toString(),l=`Here is your Code: ${s}`,d=`
    <html>
      <body style="font-family: Arial, sans-serif; text-align: center;">
        <div style="max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
          <h2 style="color: #333;">Verification Required</h2>
          <p>Thank you for using our service. Please use the following code to continue:</p>
          <div style="background-color: #f5f5f5; padding: 15px; border-radius: 4px; margin: 20px 0;">
            <p style="font-size: 24px; font-weight: bold; color: #007bff; margin: 0;">${s}</p>
          </div>
          <p style="font-size: 12px; color: #777;">This code is valid for 15 minutes.</p>
          <p><b>${t}</b></p>
        </div>
      </body>
    </html>
  `;await E.send(new f({TableName:process.env.TABLE_NAME,Item:{id:{S:o},sort:{S:s},status:{S:"pending"},timestamp:{S:r}}}));let m=new p({Source:process.env.SENDER_EMAIL,Destination:{ToAddresses:[o]},Message:{Subject:{Data:n},Body:{Text:{Data:l},Html:{Data:d}}}});try{return await g.send(m),{timestamp:r,taskToken:t,code:s,status:"sent"}}catch(i){throw new Error(`Failed to send email to ${o}: ${i instanceof Error?i.message:"Unknown error"}`)}};var h=()=>Math.floor(1e5+Math.random()*9e5).toString(),b=async e=>{console.log("Step Functions send-email handler:",JSON.stringify(e,null,2));let o=h(),{email:t,taskToken:r}=e;try{return await a({email:t,taskToken:r}),{email:e.email,code:o,status:"email_sent"}}catch(n){throw console.error("Error in step-functions send-email:",n),new Error(`SendEmailFailed: ${n instanceof Error?n.message:"Unknown error"}`)}};export{b as handler};
