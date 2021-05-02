# SHA1 Length Extension Attack

With this project, I am practicing Length Extension Attack on SHA1. 

A few thing I have been finding out during my work:
* In order to have a better understanding of the attack, I've built my own SHA1 generator. Actually, building SHA1 generator (or at least a part it) is required for implementation of the attack

* You have to known exactly the length of secret key to get the attack working. In reality, I think, this could be worked out using brute force. In my example, I made an assumption that the key length was already present (likes almost all SHA1 Length Extension Attack examples out there :D). 

* I had quite hard time trying to figure out how to deal with added HEX string value into the message. When generating SHA1 hash code for (key + origin text + HEX string texts + new appended text) using any online SHA1 generator tool, I always got different hash code rather than what was calculated in my implementation. I guess, that server would consider HEX string "\x80" e.g. as four single characters and not as a single HEX value. For this reason, new hash code via Online tool is differently calculated. You might also notice that I had to treat these HEX values separately (methods "SHA1.__convertMessageToBinary()" (line 29) and "SHA1_Length_Attack.__convertMessageToBinary()" (line 58)). Removing this rule will result the same hash code calculation likes SHA1 online tools. But you know the idea be behind it, right :P? 
