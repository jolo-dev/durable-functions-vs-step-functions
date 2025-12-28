import{SESClient as c,SendEmailCommand as u}from"@aws-sdk/client-ses";import{DynamoDBClient as p,PutItemCommand as f}from"@aws-sdk/client-dynamodb";var g=new c({}),y=new p({}),i=async o=>{let{to:r,requestId:e}=o;if(!r||!e)throw new Error("Missing required fields: to, requestId, code");let t=new Date().toISOString(),a="Demo: Your Verification Code",s=Math.floor(1e5+Math.random()*9e5).toString(),d=`Here is your Code: ${s}`,l=`
    <html>
      <body style="font-family: Arial, sans-serif; text-align: center;">
        <div style="max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
          <h2 style="color: #333;">Verification Required</h2>
          <p>Thank you for using our service. Please use the following code to continue:</p>
          <div style="background-color: #f5f5f5; padding: 15px; border-radius: 4px; margin: 20px 0;">
            <p style="font-size: 24px; font-weight: bold; color: #007bff; margin: 0;">${s}</p>
          </div>
          <p style="font-size: 12px; color: #777;">This code is valid for 15 minutes.</p>
        </div>
      </body>
    </html>
  `;await y.send(new f({TableName:process.env.TABLE_NAME,Item:{id:{S:email},sort:{S:s},requestId:{S:e},status:{S:"pending"},timestamp:{S:t}}}));let m=new u({Source:process.env.SENDER_EMAIL,Destination:{ToAddresses:[email]},Message:{Subject:{Data:a},Body:{Text:{Data:d},Html:{Data:l}}}});try{let n=await g.send(m);return{requestId:e,messageId:n.MessageId,timestamp:t,status:"sent"}}catch(n){throw new Error(`Failed to send email to ${email}: ${n instanceof Error?n.message:"Unknown error"}`)}};var h=()=>Math.floor(1e5+Math.random()*9e5).toString(),I=async o=>{console.log("Step Functions send-email handler:",JSON.stringify(o,null,2));let r=`req-${Date.now()}`,e=h();try{return await i({to:o.email,subject:"Demo: Your Verification Code",body:`Here is your Code: ${e}`,requestId:r,code:e}),{email:o.email,requestId:r,code:e,status:"email_sent"}}catch(t){throw console.error("Error in step-functions send-email:",t),new Error(`SendEmailFailed: ${t instanceof Error?t.message:"Unknown error"}`)}};export{I as handler};
