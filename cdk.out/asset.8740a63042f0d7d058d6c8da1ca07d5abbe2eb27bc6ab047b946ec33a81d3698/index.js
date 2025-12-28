"use strict";var l=Object.defineProperty;var f=Object.getOwnPropertyDescriptor;var y=Object.getOwnPropertyNames;var g=Object.prototype.hasOwnProperty;var h=(o,e)=>{for(var t in e)l(o,t,{get:e[t],enumerable:!0})},w=(o,e,t,s)=>{if(e&&typeof e=="object"||typeof e=="function")for(let n of y(e))!g.call(o,n)&&n!==t&&l(o,n,{get:()=>e[n],enumerable:!(s=f(e,n))||s.enumerable});return o};var x=o=>w(l({},"__esModule",{value:!0}),o);var k={};h(k,{handler:()=>b});module.exports=x(k);var i=require("@aws-sdk/client-ses"),r=require("@aws-sdk/client-dynamodb"),E=new i.SESClient({}),S=new r.DynamoDBClient({}),m=async o=>{console.log("send-email request",o);let{email:e,taskToken:t}=o;if(!e)throw new Error("Missing required fields: email");let s=new Date().toISOString(),n="Demo: Your Verification Code",a=Math.floor(1e5+Math.random()*9e5).toString(),c=`Here is your Code: ${a}`,p=`
    <html>
      <body style="font-family: Arial, sans-serif; text-align: center;">
        <div style="max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
          <h2 style="color: #333;">Verification Required</h2>
          <p>Thank you for using our service. Please use the following code to continue:</p>
          <div style="background-color: #f5f5f5; padding: 15px; border-radius: 4px; margin: 20px 0;">
            <p style="font-size: 24px; font-weight: bold; color: #007bff; margin: 0;">{ token: ${t}, email: ${e}, code: '${a}' }</p>
          </div>
          <p style="font-size: 12px; color: #777;">This code is valid for 15 minutes.</p>
        </div>
      </body>
    </html>
  `;await S.send(new r.PutItemCommand({TableName:process.env.TABLE_NAME,Item:{id:{S:e},sort:{S:a},status:{S:"pending"},timestamp:{S:s}}}));let u=new i.SendEmailCommand({Source:"johnyscrazy@gmail.com",Destination:{ToAddresses:[e]},Message:{Subject:{Data:n},Body:{Text:{Data:c},Html:{Data:p}}}});try{return await E.send(u),{timestamp:s,taskToken:t,code:a,status:"sent"}}catch(d){throw new Error(`Failed to send email to ${e}: ${d instanceof Error?d.message:"Unknown error"}`)}};var b=async o=>{console.log("durable-handler",o);let{body:e}=o;return{...await m({email:JSON.parse(e).email,taskToken:"callbackId"})}};0&&(module.exports={handler});
