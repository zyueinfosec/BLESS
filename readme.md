BLESS is a tool that can evaluate the security of BLE enabled Apps. Specifically, It extends from the Amandroid, which use taint analysis to detect the source and sinks. Our observation of designing such a tool is that a secure BLE app must use a key to grantee the data integrity and use a random number to defend the replay attack. Therefore, any apps without these two features are considered as insecure BLE apps.
