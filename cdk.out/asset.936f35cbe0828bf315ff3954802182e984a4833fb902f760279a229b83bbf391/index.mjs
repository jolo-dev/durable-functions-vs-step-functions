import{SESClient as m,SendEmailCommand as c}from"@aws-sdk/client-ses";import{DynamoDBClient as u,PutItemCommand as p}from"@aws-sdk/client-dynamodb";var f=new m({}),g=new u({}),s=async t=>{let{email:e}=t;if(!e)throw new Error("Missing required fields: to, requestId, code");let o=new Date().toISOString(),n="Demo: Your Verification Code",r=Math.floor(1e5+Math.random()*9e5).toString(),a=`Here is your Code: ${r}`,d=`
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
  `;await g.send(new p({TableName:process.env.TABLE_NAME,Item:{id:{S:e},sort:{S:r},status:{S:"pending"},timestamp:{S:o}}}));let l=new c({Source:process.env.SENDER_EMAIL,Destination:{ToAddresses:[e]},Message:{Subject:{Data:n},Body:{Text:{Data:a},Html:{Data:d}}}});try{let i=await f.send(l);return{timestamp:o,status:"sent"}}catch(i){throw new Error(`Failed to send email to ${e}: ${i instanceof Error?i.message:"Unknown error"}`)}};var h=()=>Math.floor(1e5+Math.random()*9e5).toString(),x=async t=>{console.log("Step Functions send-email handler:",JSON.stringify(t,null,2));let e=`req-${Date.now()}`,o=h();try{return await s({email:t.email,requestId:e,code:o}),{email:t.email,requestId:e,code:o,status:"email_sent"}}catch(n){throw console.error("Error in step-functions send-email:",n),new Error(`SendEmailFailed: ${n instanceof Error?n.message:"Unknown error"}`)}};export{x as handler};
