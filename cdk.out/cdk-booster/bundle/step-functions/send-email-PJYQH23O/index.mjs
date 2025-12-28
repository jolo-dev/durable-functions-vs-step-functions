import{SESClient as c,SendEmailCommand as u}from"@aws-sdk/client-ses";import{DynamoDBClient as p,PutItemCommand as f}from"@aws-sdk/client-dynamodb";var g=new c({}),y=new p({}),i=async r=>{let{to:t,requestId:o,code:e}=r;if(!t||!o||!e)throw new Error("Missing required fields: to, requestId, code");let s=new Date().toISOString(),a="Demo: Your Verification Code",d=`Here is your Code: ${e}`,l=`
    <html>
      <body style="font-family: Arial, sans-serif; text-align: center;">
        <div style="max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
          <h2 style="color: #333;">Verification Required</h2>
          <p>Thank you for using our service. Please use the following code to continue:</p>
          <div style="background-color: #f5f5f5; padding: 15px; border-radius: 4px; margin: 20px 0;">
            <p style="font-size: 24px; font-weight: bold; color: #007bff; margin: 0;">${e}</p>
          </div>
          <p style="font-size: 12px; color: #777;">This code is valid for 15 minutes.</p>
        </div>
      </body>
    </html>
  `;await y.send(new f({TableName:process.env.TABLE_NAME,Item:{id:{S:t},sort:{S:e},requestId:{S:o},status:{S:"pending"},timestamp:{S:s}}}));let m=new u({Source:process.env.SENDER_EMAIL,Destination:{ToAddresses:[t]},Message:{Subject:{Data:a},Body:{Text:{Data:d},Html:{Data:l}}}});try{let n=await g.send(m);return{requestId:o,messageId:n.MessageId,timestamp:s,status:"sent"}}catch(n){throw new Error(`Failed to send email to ${t}: ${n instanceof Error?n.message:"Unknown error"}`)}};var E=()=>Math.floor(1e5+Math.random()*9e5).toString(),I=async r=>{console.log("Step Functions send-email handler:",JSON.stringify(r,null,2));let t=`req-${Date.now()}`,o=E();try{return await i({to:r.email,subject:"Demo: Your Verification Code",body:`Here is your Code: ${o}`,requestId:t,code:o}),{email:r.email,requestId:t,code:o,status:"email_sent"}}catch(e){throw console.error("Error in step-functions send-email:",e),new Error(`SendEmailFailed: ${e instanceof Error?e.message:"Unknown error"}`)}};export{I as handler};
