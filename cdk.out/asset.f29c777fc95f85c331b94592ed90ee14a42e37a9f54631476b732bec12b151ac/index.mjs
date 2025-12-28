import{SESClient as c,SendEmailCommand as u}from"@aws-sdk/client-ses";import{DynamoDBClient as p,PutItemCommand as f}from"@aws-sdk/client-dynamodb";var E=new c({}),w=new p({}),s=async t=>{console.log("send-email request",t);let{email:o,taskToken:n}=t;if(!o)throw new Error("Missing required fields: email");let a=new Date().toISOString(),i="Demo: Your Verification Code",e=Math.floor(1e5+Math.random()*9e5).toString(),l=`Here is your Code: ${e}`,d=`
    <html>
      <body style="font-family: Arial, sans-serif; text-align: center;">
        <div style="max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
          <h2 style="color: #333;">Verification Required</h2>
          <p>Thank you for using our service. Please use the following code to continue:</p>
          <div style="background-color: #f5f5f5; padding: 15px; border-radius: 4px; margin: 20px 0;">
            <p style="font-size: 24px; font-weight: bold; color: #007bff; margin: 0;">{ token: ${e}, email: ${o}, code: ${e} }</p>
          </div>
          <p style="font-size: 12px; color: #777;">This code is valid for 15 minutes.</p>
        </div>
      </body>
    </html>
  `;await w.send(new f({TableName:process.env.TABLE_NAME,Item:{id:{S:o},sort:{S:e},status:{S:"pending"},timestamp:{S:a}}}));let m=new u({Source:process.env.SENDER_EMAIL,Destination:{ToAddresses:[o]},Message:{Subject:{Data:i},Body:{Text:{Data:l},Html:{Data:d}}}});try{return await E.send(m),{timestamp:a,taskToken:n,code:e,status:"sent"}}catch(r){throw new Error(`Failed to send email to ${o}: ${r instanceof Error?r.message:"Unknown error"}`)}};var h=async(t,o)=>{let{email:n}=t,[a,i]=await o.createCallback("wait-for-code",{timeout:{minutes:15}});await s({email:n,taskToken:i});let e=await a;return console.log("durable-handler",e),e};export{h as handler};
