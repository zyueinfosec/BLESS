# BLESS
### Abstract
 
BLESS is a **BLE** Application **S**ecurity **S**canning framework  to automatically uncover vulnerable BLE enabled apps. Specifically, it extends from the Amandroid which is a static taint analysis tool to detect vulnerabilities of Android Apps. Our observation is that a secure BLE app must use a key to defend spoofing attacks, and use a random number to defend the replay attacks. Therefore, any apps without the above features are considered as insecure BLE apps.

##### How to Use it?

1. These scripts require Java v1.6+ and Amandroid (and all dependencies) to be installed on your system.
	 > *Please refer to the following url to find out how to set up the Amandroid:*
	 > http://pag.arguslab.org/argus-saf 

2. The following Java file is used to configure the project. Please ensure that all configureations are ready before you run the framework.
 	> Path: org.argus.amandroid.alir.securityconfig==> RuntimeConfig.java
	- executePath : a folder contains sample Android applications for testing our tools.
	- resPath : the result will save into this folder.
	- logPath : a folder that used to save the log. The log will record files that couldn't be analysed due to some error. 
3. Run the framework:
	> Path : org.argus.amandroid.alir.componentSummary.main==> TaintTask.scala
	```
	right click ------> Run As ------> Scala Application
	
Enjoy!

For more details please refer to our INFOCOM 2020 paper. (BLESS: A BLE Application Security Scanning Framework: https://ieeexplore.ieee.org/document/9155473) 

# Citing
If you create a research work that uses our work, please cite the associated paper:

@inproceedings{zhang2020bless,
  author    = {Yue Zhang and
               Jian Weng and
               Zhen Ling and
               Bryan Pearson and
               Xinwen Fu},
  title     = {{BLESS:} {A} {BLE} Application Security Scanning Framework},
  booktitle = {39th {IEEE} Conference on Computer Communications, {INFOCOM} 2020,
               Toronto, ON, Canada, July 6-9, 2020},
  pages     = {636--645},
  publisher = {{IEEE}},
  year      = {2020},
  doi       = {10.1109/INFOCOM41043.2020.9155473},
  timestamp = {Mon, 10 Aug 2020 17:45:33 +0200}
}
