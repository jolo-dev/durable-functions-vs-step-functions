import{SESClient as m,SendEmailCommand as c}from"@aws-sdk/client-ses";import{DynamoDBClient as u,PutItemCommand as p}from"@aws-sdk/client-dynamodb";var f=new m({}),g=new u({}),i=async t=>{let{email:e}=t;if(!e)throw new Error("Missing required fields: to, requestId, code");let o=new Date().toISOString(),r="Demo: Your Verification Code",s=Math.floor(1e5+Math.random()*9e5).toString(),a=`Here is your Code: ${s}`,d=`
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
  `;await g.send(new p({TableName:process.env.TABLE_NAME,Item:{id:{S:e},sort:{S:s},status:{S:"pending"},timestamp:{S:o}}}));let l=new c({Source:process.env.SENDER_EMAIL,Destination:{ToAddresses:[e]},Message:{Subject:{Data:r},Body:{Text:{Data:a},Html:{Data:d}}}});try{let n=await f.send(l);return{requestId,messageId:n.MessageId,timestamp:o,status:"sent"}}catch(n){throw new Error(`Failed to send email to ${e}: ${n instanceof Error?n.message:"Unknown error"}`)}};var y=()=>Math.floor(1e5+Math.random()*9e5).toString(),x=async t=>{console.log("Step Functions send-email handler:",JSON.stringify(t,null,2));let e=`req-${Date.now()}`,o=y();try{return await i({to:t.email,subject:"Demo: Your Verification Code",body:`Here is your Code: ${o}`,requestId:e,code:o}),{email:t.email,requestId:e,code:o,status:"email_sent"}}catch(r){throw console.error("Error in step-functions send-email:",r),new Error(`SendEmailFailed: ${r instanceof Error?r.message:"Unknown error"}`)}};export{x as handler};
