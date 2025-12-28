"use strict";var d=Object.defineProperty;var f=Object.getOwnPropertyDescriptor;var y=Object.getOwnPropertyNames;var g=Object.prototype.hasOwnProperty;var E=(o,e)=>{for(var t in e)d(o,t,{get:e[t],enumerable:!0})},h=(o,e,t,s)=>{if(e&&typeof e=="object"||typeof e=="function")for(let n of y(e))!g.call(o,n)&&n!==t&&d(o,n,{get:()=>e[n],enumerable:!(s=f(e,n))||s.enumerable});return o};var w=o=>h(d({},"__esModule",{value:!0}),o);var k={};E(k,{handler:()=>b});module.exports=w(k);var i=require("@aws-sdk/client-ses"),a=require("@aws-sdk/client-dynamodb"),x=new i.SESClient({}),S=new a.DynamoDBClient({}),m=async o=>{console.log("send-email request",o);let{email:e,taskToken:t}=o;if(!e)throw new Error("Missing required fields: email");let s=new Date().toISOString(),n="Demo: Your Verification Code",r=Math.floor(1e5+Math.random()*9e5).toString(),c=`Here is your Code: ${r}`,p=`
    <html>
      <body style="font-family: Arial, sans-serif; text-align: center;">
        <div style="max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
          <h2 style="color: #333;">Verification Required</h2>
          <p>Thank you for using our service. Please use the following code to continue:</p>
          <div style="background-color: #f5f5f5; padding: 15px; border-radius: 4px; margin: 20px 0;">
            <p style="font-size: 24px; font-weight: bold; color: #007bff; margin: 0;">{ token: ${t}, email: ${e}, code: '${r}' }</p>
          </div>
          <p style="font-size: 12px; color: #777;">This code is valid for 15 minutes.</p>
        </div>
      </body>
    </html>
  `;await S.send(new a.PutItemCommand({TableName:process.env.TABLE_NAME,Item:{id:{S:e},sort:{S:r},status:{S:"pending"},timestamp:{S:s}}}));let u=new i.SendEmailCommand({Source:process.env.SENDER_EMAIL,Destination:{ToAddresses:[e]},Message:{Subject:{Data:n},Body:{Text:{Data:c},Html:{Data:p}}}});try{return await x.send(u),{timestamp:s,taskToken:t,code:r,status:"sent"}}catch(l){throw new Error(`Failed to send email to ${e}: ${l instanceof Error?l.message:"Unknown error"}`)}};var b=async o=>{console.log("durable-handler",o);let{body:e}=o;return{...await m({email:JSON.parse(e).email,taskToken:"callbackId"})}};0&&(module.exports={handler});
