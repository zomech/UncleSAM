# UncleSAM

UncleSAM is a simple tool for extracting ntlm password hashes.

The tool accesses the registry hives directly from the Disk and extract the ntlm hashes from the SAM, using it's own set of registry APIs for the purpose of parsing the registry hives.

UncleSAM is an experimental tool written for the purpose of learning about the registry file structure, registry internals, how ntlm hashes are stored and how to decrypt them and Disk IO APIs.


\
References:

Registry hive structure:

https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md#windows-vista-sam-hive

https://binaryforay.blogspot.com/2015/01/registry-hive-basics.html

https://2017.zeronights.org/wp-content/uploads/materials/ZN17-Suhanov-Registry.pdf


SAM structure and password extraction:

http://www.insecurity.be/blog/2018/01/21/retrieving-ntlm-hashes-and-what-changed-technical-writeup/

http://moyix.blogspot.com/2008/02/syskey-and-sam.html

http://www.beginningtoseethelight.org/ntsecurity/index.htm
