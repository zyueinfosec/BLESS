# BLESS
### Abstract


BLESS is a **BLE** Application **S**ecurity **S**canning framework that can evaluate the security of BLE enabled Apps. Specifically, It extends from the Amandroid  which use taint analysis to detect vulnerabilities of Android Apps. Our observation of designing such a tool is that a secure BLE app must use a key to grantee the data integrity and use a random number to defend the replay attack. Therefore, any apps without these two features are considered as insecure BLE apps.

##### How to Use it?

1. These scripts require Java v1.6+ and Amandroid (and all dependencies) to be installed on your system.
	 > *Please refer to the following url to find out how to set up the Amandroid:*
	 > http://pag.arguslab.org/argus-saf 

2. The following Java file is used to configure the project. Please make sure all configureation is done before you run the framework.
 	> Path: org.argus.amandroid.alir.securityconfig==> RuntimeConfig.java
	- executePath : a folder contains sample Android applications for testing our tools.
	- resPath : the result will save into this folder.
	- logPath : a folder that used to save the log. The log will record files that couldn't be analysed due to some error. 
3. Run the framework:
	> Path : org.argus.amandroid.alir.componentSummary.main==> TaintTask.scala
	```
	right click ------> Run As ------> Scala Application
	
Enjoy!

 

More details please refer to our paper. (To be appeared soon) 
