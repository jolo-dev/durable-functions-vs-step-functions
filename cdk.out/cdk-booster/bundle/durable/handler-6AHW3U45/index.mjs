import{SESClient as c,SendEmailCommand as p}from"@aws-sdk/client-ses";import{DynamoDBClient as u,PutItemCommand as f}from"@aws-sdk/client-dynamodb";var w=new c({}),E=new u({}),r=async o=>{console.log("send-email request",o);let{email:e,taskToken:i}=o;if(!e)throw new Error("Missing required fields: email");let a=new Date().toISOString(),s="Demo: Your Verification Code",t=Math.floor(1e5+Math.random()*9e5).toString(),l=`Here is your Code: ${t}`,d=`
    <html>
      <body style="font-family: Arial, sans-serif; text-align: center;">
        <div style="max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
          <h2 style="color: #333;">Verification Required</h2>
          <p>Thank you for using our service. Please use the following code to continue:</p>
          <div style="background-color: #f5f5f5; padding: 15px; border-radius: 4px; margin: 20px 0;">
            <p style="font-size: 24px; font-weight: bold; color: #007bff; margin: 0;">{ token: ${t}, email: ${e}, code: ${t} }</p>
          </div>
          <p style="font-size: 12px; color: #777;">This code is valid for 15 minutes.</p>
        </div>
      </body>
    </html>
  `;await E.send(new f({TableName:process.env.TABLE_NAME,Item:{id:{S:e},sort:{S:t},status:{S:"pending"},timestamp:{S:a}}}));let m=new p({Source:process.env.SENDER_EMAIL,Destination:{ToAddresses:[e]},Message:{Subject:{Data:s},Body:{Text:{Data:l},Html:{Data:d}}}});try{return await w.send(m),{timestamp:a,taskToken:i,code:t,status:"sent"}}catch(n){throw new Error(`Failed to send email to ${e}: ${n instanceof Error?n.message:"Unknown error"}`)}};var b=async(o,e)=>{await e.waitForCallback(async a=>await r({email:o.email,taskToken:o.taskToken}))==="APPROVED"?await e.step(async()=>await performAction(todo)):await e.step(async()=>await recordRejected(todo,o.approverEmail))};export{b as handler};
