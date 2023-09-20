# Canteen
Recurrence of vulnerabilities
There is a problem with Alibaba Cloud OSS AccessKey leakage in the Xiaoniuyun Canteen Smart Canteen Management System. Attackers can obtain sensitive information and control cloud servers by obtaining the AccessKey
Case reproduction As shown, this is a test site

![image](https://github.com/dubin12345/Canteen/assets/144758348/4fd75650-eaff-4921-bad2-4722dd6521ec)
View the front-end code of the website and find multiple JSs
![image](https://github.com/dubin12345/Canteen/assets/144758348/6b4d9311-3496-47db-9142-32a993678e06)
Splice the front-end JS fields and wait for multiple front-end static page URLs

![image](https://github.com/dubin12345/Canteen/assets/144758348/91afe9dc-3350-4d7a-8690-65792f3b51dd)

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

      ![image](https://github.com/dubin12345/Canteen/assets/144758348/f105de82-4b4d-4caf-9048-fef893a44627)
    Accessing the vulnerable URL and finding the accessKeyId and accessKeySecret
    ![image](https://github.com/dubin12345/Canteen/assets/144758348/7493b58c-7982-4ab2-a3d8-60f908a9212d)
    Use Alibaba Cloud Key Leakage Utilization Tool to Obtain Permissions
    ![image](https://github.com/dubin12345/Canteen/assets/144758348/84137d38-253b-44be-8080-75882a318894)
    







