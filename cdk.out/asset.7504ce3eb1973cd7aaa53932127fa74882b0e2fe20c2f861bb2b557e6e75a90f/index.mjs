import{SESClient as c,SendEmailCommand as u}from"@aws-sdk/client-ses";import{DynamoDBClient as p,PutItemCommand as f}from"@aws-sdk/client-dynamodb";var E=new c({}),w=new p({}),s=async t=>{console.log("send-email request",t);let{email:e,taskToken:i}=t;if(!e)throw new Error("Missing required fields: email");let n=new Date().toISOString(),a="Demo: Your Verification Code",o=Math.floor(1e5+Math.random()*9e5).toString(),l=`Here is your Code: ${o}`,d=`
    <html>
      <body style="font-family: Arial, sans-serif; text-align: center;">
        <div style="max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
          <h2 style="color: #333;">Verification Required</h2>
          <p>Thank you for using our service. Please use the following code to continue:</p>
          <div style="background-color: #f5f5f5; padding: 15px; border-radius: 4px; margin: 20px 0;">
            <p style="font-size: 24px; font-weight: bold; color: #007bff; margin: 0;">{ token: ${o}, email: ${e}, code: ${o} }</p>
          </div>
          <p style="font-size: 12px; color: #777;">This code is valid for 15 minutes.</p>
        </div>
      </body>
    </html>
  `;await w.send(new f({TableName:process.env.TABLE_NAME,Item:{id:{S:e},sort:{S:o},status:{S:"pending"},timestamp:{S:n}}}));let m=new u({Source:process.env.SENDER_EMAIL,Destination:{ToAddresses:[e]},Message:{Subject:{Data:a},Body:{Text:{Data:l},Html:{Data:d}}}});try{return await E.send(m),{timestamp:n,taskToken:i,code:o,status:"sent"}}catch(r){throw new Error(`Failed to send email to ${e}: ${r instanceof Error?r.message:"Unknown error"}`)}};var h=async(t,e)=>{let{email:i}=t,[n,a]=await e.createCallback("wait-for-code",{timeout:{minutes:15}});await s({email:i,taskToken:a})};export{h as handler};
