# SimpleCrypt
## What is SimpleCrypt?
Whilst working on an encryption/decryption assignment for an online course I found out that Intel had published a library to allow for AES encryption and decryption directly on the CPU. As a challenge I decided to write my own library that will handle this. 

## Who is SimpleCrypt for?
No one really. At this stage I strongly recommend you do not use my library for actual encryption/decryption that needs to be safe. Stick with existing implementations out there. I currently do not have the knowledge to safely say my implementation is secure, and until I can do this I strongly recommend not using this library in any serious work. However, if you want to play around with encryption and decryption using `AES CTR` and `AES CBC` you are more than welcome to use this Library.

## What is the plan for SimpleCrypt?
For now it is just a little repo project that I will maintain and add to when ever I have time. It is mainly going to be a place where I can practice cryptography algorithms I learn by implementing them and playing around with them. Out of personal interest I will be implementing these firstly solely using Intel Intrinsics, and then later in a platform independent (c focused) way and a version that makes use of AMDs Intrinsics.  If anyone has any issues, tips, or just wants to help make a Library that could become useful in the future, feel free to help.

# Documentation
https://jniegsch.github.io/SimpleCrypt/
