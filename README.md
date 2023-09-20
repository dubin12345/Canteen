# Canteen
Recurrence of vulnerabilities
There is a problem with Alibaba Cloud OSS AccessKey leakage in the Xiaoniuyun Canteen Smart Canteen Management System. Attackers can obtain sensitive information and control cloud servers by obtaining the AccessKey

Affected version:<=1120
Case reproduction As shown, this is a test site

![image](https://github.com/dubin12345/Canteen/assets/144758348/bd2b97b1-6dec-4cfd-979a-df1d0a18c19f)


View the front-end code of the website and find multiple JSs

![image](https://github.com/dubin12345/Canteen/assets/144758348/ab462f66-a804-4f7e-b032-c9d425c50754)


Splice the front-end JS fields and wait for multiple front-end static page URLs

![image](https://github.com/dubin12345/Canteen/assets/144758348/0bc4f9dd-d23d-4465-94be-e8a145482f41)


Detect POC：

id: xiaoniuali-key
 
info:
  name: xiaoniuali-key
  author: dubin
  severity: critical
  tags: xiaoniu
 
requests:
  - method: GET
    path:
      - "{{BaseURL}}"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: word
        words:
          - "accessKeySecret"

    ![image](https://github.com/dubin12345/Canteen/assets/144758348/9d178ced-527d-4f03-978e-fc094a6069b3)

    
    Accessing the vulnerable URL and finding the accessKeyId and accessKeySecret
    
   ![image](https://github.com/dubin12345/Canteen/assets/144758348/e6e0a1d8-9098-4871-81a1-f8f1bb0968d3)

    
    Use Alibaba Cloud Key Leakage Utilization Tool to Obtain Permissions
    
   ![image](https://github.com/dubin12345/Canteen/assets/144758348/c17e8424-ab1c-4b19-81c7-ef90c9ef366b)

    







