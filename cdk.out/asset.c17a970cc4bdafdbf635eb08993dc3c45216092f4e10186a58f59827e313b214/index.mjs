import{SESClient as m,SendEmailCommand as c}from"@aws-sdk/client-ses";import{DynamoDBClient as u,PutItemCommand as p}from"@aws-sdk/client-dynamodb";var f=new m({}),g=new u({}),i=async t=>{let{email:e}=t;if(!e)throw new Error("Missing required fields: to, requestId, code");let n=new Date().toISOString(),o="Demo: Your Verification Code",r=Math.floor(1e5+Math.random()*9e5).toString(),a=`Here is your Code: ${r}`,d=`
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
  `;await g.send(new p({TableName:process.env.TABLE_NAME,Item:{id:{S:e},sort:{S:r},status:{S:"pending"},timestamp:{S:n}}}));let l=new c({Source:process.env.SENDER_EMAIL,Destination:{ToAddresses:[e]},Message:{Subject:{Data:o},Body:{Text:{Data:a},Html:{Data:d}}}});try{return{messageId:(await f.send(l)).MessageId,timestamp:n,status:"sent"}}catch(s){throw new Error(`Failed to send email to ${e}: ${s instanceof Error?s.message:"Unknown error"}`)}};var h=()=>Math.floor(1e5+Math.random()*9e5).toString(),x=async t=>{console.log("Step Functions send-email handler:",JSON.stringify(t,null,2));let e=`req-${Date.now()}`,n=h();try{return await i({email:t.email}),{email:t.email,requestId:e,code:n,status:"email_sent"}}catch(o){throw console.error("Error in step-functions send-email:",o),new Error(`SendEmailFailed: ${o instanceof Error?o.message:"Unknown error"}`)}};export{x as handler};
